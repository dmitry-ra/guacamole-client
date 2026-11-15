"""Proxy rendering and real nginx syntax; never start a listener."""
import importlib.util
import hashlib
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
        self.assertEqual(text.count('if (!-f /run/guacamole-portal/ready)'), 7)
        self.assertIn('proxy_set_header X-Forwarded-For $remote_addr;', text)
        self.assertIn('limit_req zone=guacamole_portal_auth burst=10 nodelay;', text)
        self.assertIn('proxy_pass http://127.0.0.1:10474/guacamole/;', text)

    def test_port_cannot_inject_configuration(self):
        for value in (0, 80, 65536, True, '10474; bad'):
            with self.assertRaises(ValueError):
                proxy.render(catalog.parse(configuration()), value)

    def test_framing_exception_matches_reviewed_static_empty_native_document(self):
        path=Path(__file__).resolve().parents[2]/'guacamole/src/main/frontend/src/app/element/templates/blank.html'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         '92cf9c0ad9225f4ad7efdbbe07233988f9d0a949bc65fbfed5d9d7d21faa72e3',
                         'Review the exact framing exception if this native document changes')

    def test_only_exact_empty_resize_document_allows_same_origin_framing(self):
        text = proxy.render(catalog.parse(configuration()), 10474)
        locations = text.count('location ')
        for header in ('add_header Content-Security-Policy "frame-ancestors \'none\';" always;',
                       'add_header X-Frame-Options "DENY" always;'):
            self.assertEqual(text.count(header), locations-1)
        self.assertEqual(text.count('add_header X-Content-Type-Options "nosniff" always;'), locations)
        path='/desktop/app/app/element/templates/blank.html'
        self.assertEqual(text.count('location = '+path+' {'),1)
        self.assertNotIn('location ^~ '+path,text)
        block=text.split('location = '+path+' {',1)[1].split('location ^~ /desktop/app/api/tokens',1)[0]
        self.assertIn('proxy_pass http://127.0.0.1:10474/guacamole/app/element/templates/blank.html;',block)
        self.assertIn('limit_except GET { deny all; }',block)
        self.assertIn('if (!-f /run/guacamole-portal/ready)',block)
        self.assertIn('add_header Cache-Control "no-store" always;',block)
        for header in ('Content-Security-Policy "frame-ancestors \'self\';"','X-Frame-Options "SAMEORIGIN"'):
            self.assertEqual(text.count(header),1)
            self.assertIn(header,block)

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
