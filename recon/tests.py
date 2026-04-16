from unittest.mock import patch
from django.test import TestCase
from .scanners import _is_internal_ip, _validate_target


class InternalIPDetectionTests(TestCase):
    def test_loopback_is_internal(self):
        self.assertTrue(_is_internal_ip('127.0.0.1'))
        self.assertTrue(_is_internal_ip('127.1.2.3'))

    def test_rfc1918_is_internal(self):
        self.assertTrue(_is_internal_ip('10.0.0.1'))
        self.assertTrue(_is_internal_ip('172.16.0.1'))
        self.assertTrue(_is_internal_ip('192.168.1.1'))

    def test_link_local_is_internal(self):
        self.assertTrue(_is_internal_ip('169.254.169.254'))  # AWS metadata
        self.assertTrue(_is_internal_ip('169.254.1.1'))

    def test_multicast_is_internal(self):
        self.assertTrue(_is_internal_ip('224.0.0.1'))

    def test_ipv6_loopback_is_internal(self):
        self.assertTrue(_is_internal_ip('::1'))

    def test_public_ip_not_internal(self):
        self.assertFalse(_is_internal_ip('8.8.8.8'))
        self.assertFalse(_is_internal_ip('1.1.1.1'))

    def test_invalid_ip_not_internal(self):
        self.assertFalse(_is_internal_ip('not-an-ip'))
        self.assertFalse(_is_internal_ip(''))


class ValidateTargetTests(TestCase):
    def test_localhost_blocked(self):
        for t in ('localhost', '127.0.0.1', '0.0.0.0', '::1'):
            with self.assertRaises(ValueError):
                _validate_target(t)

    def test_url_scheme_stripped(self):
        with patch('recon.scanners.socket.gethostbyname', return_value='8.8.8.8'):
            host, ip = _validate_target('https://example.com/foo/bar')
            self.assertEqual(host, 'example.com')
            self.assertEqual(ip, '8.8.8.8')

    def test_port_stripped(self):
        with patch('recon.scanners.socket.gethostbyname', return_value='8.8.8.8'):
            host, _ = _validate_target('example.com:8080')
            self.assertEqual(host, 'example.com')

    def test_private_resolution_blocked(self):
        """SSRF: if DNS returns a private IP, target must be rejected."""
        with patch('recon.scanners.socket.gethostbyname', return_value='10.0.0.5'):
            with self.assertRaises(ValueError) as cm:
                _validate_target('internal.example.com')
            self.assertIn('internal', str(cm.exception).lower())

    def test_aws_metadata_blocked(self):
        with patch('recon.scanners.socket.gethostbyname', return_value='169.254.169.254'):
            with self.assertRaises(ValueError):
                _validate_target('metadata.internal')

    def test_unresolvable_host_raises(self):
        import socket as _socket
        with patch('recon.scanners.socket.gethostbyname', side_effect=_socket.gaierror):
            with self.assertRaises(ValueError):
                _validate_target('does-not-exist.invalid')

    def test_valid_public_target_returns_hostname_and_ip(self):
        with patch('recon.scanners.socket.gethostbyname', return_value='93.184.216.34'):
            host, ip = _validate_target('example.com')
            self.assertEqual(host, 'example.com')
            self.assertEqual(ip, '93.184.216.34')
