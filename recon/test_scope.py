from types import SimpleNamespace
from unittest.mock import patch, Mock
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from accounts.models import User
from engagements.models import Engagement, EngagementMember
from .models import ReconScan, ScheduledScan, ScanPipeline
from .scope import ScanScope, ScopeViolation
from .scanners import run_scan, scan_ports, scan_subdomains
from .tasks import run_scan_async, run_scheduled_scan, run_pipeline


class ScopeRuleTests(SimpleTestCase):
    def policy(self, allowed='example.com', excluded='', locked=True):
        return ScanScope(SimpleNamespace(in_scope=allowed, out_of_scope=excluded, roe_signed_off=locked, status='planning'))

    def test_exact_host_does_not_include_subdomains_or_suffix_lookalikes(self):
        policy = self.policy()
        self.assertEqual(policy.check('EXAMPLE.COM.'), 'example.com')
        for target in ['api.example.com', 'example.com.attacker.test', 'badexample.com']:
            with self.subTest(target=target), self.assertRaises(ScopeViolation): policy.check(target)

    def test_wildcard_is_explicit_and_exclusions_win(self):
        policy = self.policy('example.com\n*.example.com', 'admin.example.com\n*.private.example.com')
        self.assertEqual(policy.check('api.example.com'), 'api.example.com')
        for target in ['admin.example.com', 'db.private.example.com']:
            with self.assertRaises(ScopeViolation): policy.check(target)
        with self.assertRaises(ScopeViolation): self.policy('*.example.com').check('example.com')

    def test_cidr_authorizes_single_ip_and_excluded_network_wins(self):
        policy = self.policy('93.184.216.0/24', '93.184.216.128/25')
        policy.check('93.184.216.34')
        with self.assertRaises(ScopeViolation): policy.check('93.184.216.200')
        with self.assertRaises(ScopeViolation): policy.check('93.184.216.0/24')

    def test_url_scope_does_not_authorize_hostwide_scan(self):
        with self.assertRaises(ScopeViolation): self.policy('https://example.com/app').check('example.com')
        with self.assertRaises(ScopeViolation): self.policy('example.com', 'https://example.com/private').check('example.com')

    def test_invalid_input_and_unconfirmed_scope_fail_closed(self):
        for target in ['https://example.com/app', 'example.com:8443', 'example.com/a', '-option', 'example.com other.test', '::1']:
            with self.subTest(target=target), self.assertRaises(ScopeViolation): self.policy().check(target)
        with self.assertRaises(ScopeViolation): self.policy(locked=False)
        with self.assertRaises(ScopeViolation): self.policy(excluded='not valid scope')


@override_settings(MFA_REQUIRED_ROLES=[])
class ScanExecutionScopeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('operator', role='pentester')
        self.eng = Engagement.objects.create(name='Assessment', engagement_type='webapp', in_scope='example.com\n*.example.com', out_of_scope='private.example.com', roe_signed_off=True)
        EngagementMember.objects.create(engagement=self.eng, user=self.user, role='lead')
        self.client.force_login(self.user)

    def test_manual_entry_rejects_target_without_running_scanner(self):
        scanner = Mock(return_value=[])
        with patch.dict('recon.scanners.SCANNERS', {'port_scan':scanner}):
            response = self.client.post(reverse('recon:start_scan', args=[self.eng.pk]), {'scan_type':'port_scan', 'target':'other.test'})
        self.assertEqual(response.status_code, 302)
        scanner.assert_not_called()
        self.assertFalse(ReconScan.objects.exists())

    def test_manual_allowed_scan_uses_dispatch_policy(self):
        scanner = Mock(return_value=[])
        with patch.dict('recon.scanners.SCANNERS', {'port_scan':scanner}):
            self.client.post(reverse('recon:start_scan', args=[self.eng.pk]), {'scan_type':'port_scan', 'target':'example.com'})
        scanner.assert_called_once_with('example.com')
        self.assertEqual(ReconScan.objects.get().status, 'completed')

    def test_queued_scan_rechecks_lock(self):
        scan = ReconScan.objects.create(engagement=self.eng, scan_type='port_scan', target='example.com')
        Engagement.objects.filter(pk=self.eng.pk).update(roe_signed_off=False)
        scanner = Mock()
        with patch.dict('recon.scanners.SCANNERS', {'port_scan':scanner}):
            result = run_scan_async(str(scan.pk))
        scanner.assert_not_called()
        self.assertEqual(result['status'], 'failed')

    def test_scheduled_scan_rechecks_changed_exclusions(self):
        schedule = ScheduledScan.objects.create(engagement=self.eng, scan_type='port_scan', target='example.com', created_by=self.user)
        Engagement.objects.filter(pk=self.eng.pk).update(out_of_scope='example.com')
        scanner = Mock()
        with patch.dict('recon.scanners.SCANNERS', {'port_scan':scanner}):
            result = run_scheduled_scan(str(schedule.pk))
        scanner.assert_not_called()
        self.assertEqual(result['status'], 'failed')

    def test_pipeline_skips_out_of_scope_discovery_and_records_reason(self):
        pipeline = ScanPipeline.objects.create(engagement=self.eng, name='Test', target='example.com', steps=['subdomain', 'port_scan'], started_by=self.user)
        discover = Mock(return_value=[{'hostname':'api.example.com'}, {'hostname':'private.example.com'}, {'hostname':'elsewhere.test'}])
        ports = Mock(return_value=[])
        with patch.dict('recon.scanners.SCANNERS', {'subdomain':discover, 'port_scan':ports}):
            result = run_pipeline(str(pipeline.pk))
        self.assertEqual(result['status'], 'completed')
        self.assertEqual([call.args[0] for call in ports.call_args_list], ['example.com', 'api.example.com'])
        self.assertEqual(len(result['results_summary']['port_scan']['blocked']), 2)
        self.assertEqual(pipeline.scans.count(), 3)

    def test_pipeline_rechecks_scope_between_steps(self):
        pipeline = ScanPipeline.objects.create(engagement=self.eng, name='Test', target='example.com', steps=['subdomain', 'port_scan'], started_by=self.user)
        def discover(target):
            Engagement.objects.filter(pk=self.eng.pk).update(roe_signed_off=False)
            return []
        ports = Mock()
        with patch.dict('recon.scanners.SCANNERS', {'subdomain':discover, 'port_scan':ports}):
            result = run_pipeline(str(pipeline.pk))
        self.assertEqual(result['status'], 'failed')
        ports.assert_not_called()

    def test_failed_step_does_not_report_pipeline_success(self):
        pipeline = ScanPipeline.objects.create(engagement=self.eng, name='Test', target='example.com', steps=['port_scan'], started_by=self.user)
        with patch.dict('recon.scanners.SCANNERS', {'port_scan':Mock(side_effect=RuntimeError('probe failed'))}):
            result = run_pipeline(str(pipeline.pk))
        self.assertEqual(result['status'], 'failed')

    def test_resolved_excluded_ip_never_reaches_port_probe(self):
        Engagement.objects.filter(pk=self.eng.pk).update(out_of_scope='93.184.216.0/24')
        with patch.dict('recon.scanners.SCANNERS', {'port_scan':scan_ports}), patch('recon.scanners.socket.gethostbyname', return_value='93.184.216.34'), patch('recon.scanners._check_port') as probe:
            with self.assertRaises(ScopeViolation): run_scan('port_scan', 'example.com', engagement_id=self.eng.pk)
        probe.assert_not_called()

    def test_subdomain_enumeration_does_not_broaden_to_parent(self):
        Engagement.objects.filter(pk=self.eng.pk).update(in_scope='api.example.com\n*.api.example.com', out_of_scope='private.api.example.com')
        with patch.dict('recon.scanners.SCANNERS', {'subdomain':scan_subdomains}), patch('recon.scanners.SUBDOMAIN_WORDLIST', ['www', 'private']), patch('recon.scanners.socket.gethostbyname', return_value='93.184.216.34') as resolve:
            results = run_scan('subdomain', 'api.example.com', engagement_id=self.eng.pk)
        queried = [call.args[0] for call in resolve.call_args_list]
        self.assertNotIn('example.com', queried)
        self.assertNotIn('www.example.com', queried)
        self.assertNotIn('private.api.example.com', queried)
        self.assertEqual({result['hostname'] for result in results}, {'api.example.com', 'www.api.example.com'})
