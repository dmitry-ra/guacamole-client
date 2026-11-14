"""Proxy rendering and real nginx syntax; never start a listener."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from test_catalog import configuration
import catalog

SPEC = importlib.util.spec_from_file_location('portal_proxy', Path(__file__).parent/'tools/render_proxy.py')
proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proxy)


class ProxyTests(unittest.TestCase):
    def test_default_and_explicit_links_are_quoted_and_gated(self):
        text = proxy.render(catalog.parse(configuration()), 10474)
        self.assertIn('return 302 "/desktop/app/#/?wrdp-target=desktop-a";', text)
        self.assertIn('location = /desktop/connect/desktop-b', text)
        self.assertIn('location ^~ /desktop/connect/ {\n    return 404;', text)
        self.assertEqual(text.count('if (!-f /run/guacamole-portal/ready)'), 6)
        self.assertIn('proxy_set_header X-Forwarded-For $remote_addr;', text)
        self.assertIn('limit_req zone=guacamole_portal_auth burst=10 nodelay;', text)
        self.assertIn('proxy_pass http://127.0.0.1:10474/guacamole/;', text)

    def test_port_cannot_inject_configuration(self):
        for value in (0, 80, 65536, True, '10474; bad'):
            with self.assertRaises(ValueError):
                proxy.render(catalog.parse(configuration()), value)

    def test_every_generated_location_explicitly_denies_framing(self):
        text = proxy.render(catalog.parse(configuration()), 10474)
        locations = text.count('location ')
        for header in ('add_header Content-Security-Policy "frame-ancestors \'none\';" always;',
                       'add_header X-Frame-Options "DENY" always;',
                       'add_header X-Content-Type-Options "nosniff" always;'):
            self.assertEqual(text.count(header), locations)

    @unittest.skipUnless(shutil.which('nginx'), 'nginx unavailable')
    def test_real_nginx_accepts_snippet_without_starting_server(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root/'portal.conf').write_text(proxy.render(catalog.parse(configuration()), 10474))
            (root/'nginx.conf').write_text(
                f'pid {root}/nginx.pid; error_log {root}/error.log; events {{}}\n'
                'http { access_log off; limit_req_zone $binary_remote_addr zone=guacamole_portal_auth:1m rate=6r/m; '
                f'server {{ listen 127.0.0.1:10479; include {root}/portal.conf; }} }}\n')
            result = subprocess.run([shutil.which('nginx'), '-t', '-p', str(root), '-c', str(root/'nginx.conf')],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
