from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.test import TestCase, Client, override_settings
from django.urls import reverse

from accounts.models import User
from engagements.models import Engagement, EngagementMember, ActivityLog
from recon.models import DiscoveredHost
from .crypto import encrypt_secret, decrypt_secret
from .models import Credential


class CryptoRoundTripTests(TestCase):
    def test_roundtrip_non_empty(self):
        self.assertEqual(decrypt_secret(encrypt_secret('hunter2')), 'hunter2')

    def test_empty_stays_empty(self):
        self.assertEqual(encrypt_secret(''), '')
        self.assertEqual(decrypt_secret(''), '')

    def test_ciphertext_is_not_plaintext(self):
        ct = encrypt_secret('hunter2')
        self.assertNotIn('hunter2', ct)

    def test_invalid_token_returns_empty(self):
        self.assertEqual(decrypt_secret('not-a-fernet-token'), '')

    def test_explicit_vault_master_key_is_used(self):
        key = Fernet.generate_key().decode()
        with override_settings(VAULT_MASTER_KEY=key):
            ct = encrypt_secret('hunter2')
            self.assertEqual(decrypt_secret(ct), 'hunter2')
            # Raw Fernet with the same key must decrypt the ciphertext
            self.assertEqual(Fernet(key.encode()).decrypt(ct.encode()).decode(), 'hunter2')

    def test_missing_key_in_production_raises(self):
        import credentials.crypto as crypto_mod
        crypto_mod._dev_warning_emitted = False
        with override_settings(DEBUG=False, VAULT_MASTER_KEY=''):
            with self.assertRaises(ImproperlyConfigured):
                encrypt_secret('anything')


class RotateVaultKeyCommandTests(TestCase):
    def setUp(self):
        user = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='Rotate', client_name='ACME', created_by=user,
        )

    def test_rotation_preserves_plaintext(self):
        key_a = Fernet.generate_key().decode()
        key_b = Fernet.generate_key().decode()

        # Encrypt under key_a
        with override_settings(VAULT_MASTER_KEY=key_a):
            cred = Credential.objects.create(
                engagement=self.engagement,
                username='admin',
                secret_encrypted=encrypt_secret('hunter2'),
            )
            ciphertext_a = cred.secret_encrypted

        # Rotate to key_b
        with override_settings(VAULT_MASTER_KEY=key_b):
            call_command('rotate_vault_key', '--old-key', key_a, '--new-key', key_b)
            cred.refresh_from_db()
            self.assertNotEqual(cred.secret_encrypted, ciphertext_a)
            # Plaintext survives the rotation when read under the new key
            self.assertEqual(decrypt_secret(cred.secret_encrypted), 'hunter2')

    def test_rotation_aborts_when_old_key_cannot_decrypt(self):
        from django.core.management.base import CommandError
        key_a = Fernet.generate_key().decode()
        key_b = Fernet.generate_key().decode()
        wrong_key = Fernet.generate_key().decode()

        with override_settings(VAULT_MASTER_KEY=key_a):
            cred = Credential.objects.create(
                engagement=self.engagement,
                username='admin',
                secret_encrypted=encrypt_secret('hunter2'),
            )
            original_ct = cred.secret_encrypted

        with self.assertRaises(CommandError):
            call_command('rotate_vault_key', '--old-key', wrong_key, '--new-key', key_b)

        # Ciphertext unchanged — rotation was atomic
        cred.refresh_from_db()
        self.assertEqual(cred.secret_encrypted, original_ct)


class CredentialModelTests(TestCase):
    def setUp(self):
        user = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='Test', client_name='ACME', created_by=user,
        )

    def test_set_secret_stores_ciphertext(self):
        c = Credential(engagement=self.engagement)
        c.set_secret('letmein')
        self.assertNotEqual(c.secret_encrypted, 'letmein')
        self.assertTrue(c.secret_encrypted)
        self.assertEqual(c.secret, 'letmein')

    def test_masked_secret_password(self):
        c = Credential(engagement=self.engagement, credential_type=Credential.Type.PASSWORD)
        c.set_secret('hunter2')
        self.assertEqual(c.masked_secret, '•' * 7)

    def test_masked_secret_hash_shows_prefix(self):
        c = Credential(engagement=self.engagement, credential_type=Credential.Type.HASH)
        c.set_secret('aad3b435b51404eeaad3b435b51404ee')
        masked = c.masked_secret
        self.assertTrue(masked.startswith('aad3'))
        self.assertIn('…', masked)

    def test_masked_secret_empty(self):
        c = Credential(engagement=self.engagement)
        self.assertEqual(c.masked_secret, '')


class CredentialAccessTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user('lead', role='pentester', password='testpass1')
        self.pt = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.rev = User.objects.create_user('rev', role='pentester', password='testpass1')
        self.cli = User.objects.create_user('cli', role='client', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='Test', client_name='ACME', created_by=self.lead,
        )
        EngagementMember.objects.create(engagement=self.engagement, user=self.lead, role='lead')
        EngagementMember.objects.create(engagement=self.engagement, user=self.pt, role='pentester')
        EngagementMember.objects.create(engagement=self.engagement, user=self.rev, role='reviewer')
        EngagementMember.objects.create(engagement=self.engagement, user=self.cli, role='client')
        self.cred = Credential.objects.create(
            engagement=self.engagement,
            credential_type=Credential.Type.PASSWORD,
            username='admin',
            secret_encrypted=encrypt_secret('hunter2'),
            found_by=self.lead,
        )

    def test_client_blocked_from_list(self):
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('credentials:list', args=[self.engagement.pk]))
        self.assertEqual(resp.status_code, 302)

    def test_client_blocked_from_reveal(self):
        self.client.login(username='cli', password='testpass1')
        resp = self.client.post(
            reverse('credentials:reveal', args=[self.engagement.pk, self.cred.pk])
        )
        self.assertEqual(resp.status_code, 302)

    def test_pentester_can_list(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('credentials:list', args=[self.engagement.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'admin')

    def test_reviewer_read_only_cannot_edit(self):
        self.client.login(username='rev', password='testpass1')
        resp = self.client.get(
            reverse('credentials:edit', args=[self.engagement.pk, self.cred.pk])
        )
        self.assertEqual(resp.status_code, 302)


class CredentialWorkflowTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user('lead', role='pentester', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='Test', client_name='ACME', created_by=self.lead,
        )
        EngagementMember.objects.create(engagement=self.engagement, user=self.lead, role='lead')
        self.host = DiscoveredHost.objects.create(
            engagement=self.engagement, hostname='web.example.com', ip_address='10.0.0.5',
        )

    def _form_data(self, **overrides):
        data = {
            'credential_type': 'password',
            'username': 'admin',
            'secret': 'hunter2',
            'hash_type': '',
            'host': '',
            'service': 'SSH',
            'source': 'bruteforce',
            'status': 'valid',
            'notes': '',
        }
        data.update(overrides)
        return data

    def test_create_encrypts_and_logs(self):
        self.client.login(username='lead', password='testpass1')
        resp = self.client.post(
            reverse('credentials:create', args=[self.engagement.pk]),
            self._form_data(),
        )
        self.assertEqual(resp.status_code, 302)
        cred = Credential.objects.get(engagement=self.engagement)
        self.assertNotEqual(cred.secret_encrypted, 'hunter2')
        self.assertEqual(cred.secret, 'hunter2')
        self.assertEqual(cred.found_by, self.lead)
        self.assertTrue(
            ActivityLog.objects.filter(
                engagement=self.engagement, action__icontains='Added credential',
            ).exists()
        )

    def test_edit_blank_secret_keeps_existing(self):
        self.client.login(username='lead', password='testpass1')
        cred = Credential.objects.create(
            engagement=self.engagement, username='svc',
            secret_encrypted=encrypt_secret('original'),
        )
        self.client.post(
            reverse('credentials:edit', args=[self.engagement.pk, cred.pk]),
            self._form_data(username='svc', secret=''),
        )
        cred.refresh_from_db()
        self.assertEqual(cred.secret, 'original')

    def test_edit_new_secret_overwrites(self):
        self.client.login(username='lead', password='testpass1')
        cred = Credential.objects.create(
            engagement=self.engagement, username='svc',
            secret_encrypted=encrypt_secret('original'),
        )
        self.client.post(
            reverse('credentials:edit', args=[self.engagement.pk, cred.pk]),
            self._form_data(username='svc', secret='rotated'),
        )
        cred.refresh_from_db()
        self.assertEqual(cred.secret, 'rotated')

    def test_reveal_returns_plaintext_and_logs(self):
        self.client.login(username='lead', password='testpass1')
        cred = Credential.objects.create(
            engagement=self.engagement, username='admin',
            secret_encrypted=encrypt_secret('hunter2'),
        )
        resp = self.client.post(
            reverse('credentials:reveal', args=[self.engagement.pk, cred.pk])
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['secret'], 'hunter2')
        self.assertTrue(
            ActivityLog.objects.filter(
                engagement=self.engagement, action__icontains='Revealed credential',
            ).exists()
        )

    def test_reveal_requires_post(self):
        self.client.login(username='lead', password='testpass1')
        cred = Credential.objects.create(
            engagement=self.engagement, secret_encrypted=encrypt_secret('x'),
        )
        resp = self.client.get(
            reverse('credentials:reveal', args=[self.engagement.pk, cred.pk])
        )
        self.assertEqual(resp.status_code, 400)

    def test_host_filter(self):
        self.client.login(username='lead', password='testpass1')
        other_host = DiscoveredHost.objects.create(
            engagement=self.engagement, hostname='db.example.com',
        )
        Credential.objects.create(
            engagement=self.engagement, username='alice', host=self.host,
            secret_encrypted=encrypt_secret('x'),
        )
        Credential.objects.create(
            engagement=self.engagement, username='bob', host=other_host,
            secret_encrypted=encrypt_secret('x'),
        )
        resp = self.client.get(
            reverse('credentials:list', args=[self.engagement.pk])
            + f'?host={self.host.pk}'
        )
        self.assertContains(resp, 'alice')
        self.assertNotContains(resp, 'bob')

    def test_delete_logs(self):
        self.client.login(username='lead', password='testpass1')
        cred = Credential.objects.create(
            engagement=self.engagement, username='toremove',
            secret_encrypted=encrypt_secret('x'),
        )
        self.client.post(
            reverse('credentials:delete', args=[self.engagement.pk, cred.pk])
        )
        self.assertFalse(Credential.objects.filter(pk=cred.pk).exists())
        self.assertTrue(
            ActivityLog.objects.filter(
                engagement=self.engagement, action__icontains='Deleted credential',
            ).exists()
        )

    def test_host_queryset_scoped_to_engagement(self):
        """Form host field only lists hosts from this engagement."""
        other_eng = Engagement.objects.create(
            name='Other', client_name='X', created_by=self.lead,
        )
        DiscoveredHost.objects.create(engagement=other_eng, hostname='leak.example.com')
        self.client.login(username='lead', password='testpass1')
        resp = self.client.get(reverse('credentials:create', args=[self.engagement.pk]))
        form = resp.context['form']
        host_names = [h.hostname for h in form.fields['host'].queryset]
        self.assertIn('web.example.com', host_names)
        self.assertNotIn('leak.example.com', host_names)
