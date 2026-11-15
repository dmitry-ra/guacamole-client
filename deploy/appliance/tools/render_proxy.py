#!/usr/bin/env python3
"""Render a protected nginx snippet for one private appliance; never install."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import catalog


def render(registry, port):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('Unprivileged loopback backend port required')
    base = '/desktop/app/'
    # General entry always reaches the chooser, even with a saved auth token.
    # Explicit /connect/ links retain direct target selection.
    default = base + '#/'
    headers = '''    add_header Cache-Control "no-store" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Content-Security-Policy "frame-ancestors 'none';" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    access_log off;
    error_log /dev/null crit;
'''
    gate = '    if (!-f /run/guacamole-portal/ready) { return 503; }\n'
    def redirect(path, destination):
        return f'location = {path} {{\n'+gate+f'    return 302 "{destination}";\n'+headers+'}\n'
    result = '# Include only in the existing HTTPS server after acceptance.\n'
    result += redirect('/desktop', '/desktop/')
    result += redirect('/desktop/', default)
    for target in registry.targets:
        result += redirect('/desktop/connect/'+target.alias, base+'#/?wrdp-target='+target.alias)
    # Unknown aliases must never silently open the configured default.
    result += 'location ^~ /desktop/connect/ {\n    return 404;\n'+headers+'}\n'
    def proxy(path, upstream, authentication=False, resize_document=False):
        text = 'location '+('= ' if resize_document else '^~ ')+path+' {\n'+gate
        text += '    if ($uri ~ "[%;]") { return 404; }\n'
        if resize_document:
            text += '    limit_except GET { deny all; }\n'
        if authentication:
            text += '    limit_req zone=guacamole_portal_auth burst=10 nodelay;\n    limit_req_status 429;\n'
        text += f'    proxy_pass http://127.0.0.1:{port}/guacamole/{upstream};\n'
        text += '''    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cookie_path /guacamole/ /desktop/app/;
'''
        if not authentication and not resize_document:
            text += '''    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 600s;
'''
        selected_headers = headers
        if resize_document:
            # Native guacResize embeds ONLY this static empty document as an
            # object. Denying its same-origin ancestors prevents resize events
            # and can leave refreshed native clients permanently IDLE.
            selected_headers = headers.replace("frame-ancestors 'none'", "frame-ancestors 'self'")
            selected_headers = selected_headers.replace('X-Frame-Options "DENY"', 'X-Frame-Options "SAMEORIGIN"')
        return text+selected_headers+'}\n'
    result += proxy('/desktop/app/app/element/templates/blank.html',
                    'app/element/templates/blank.html', resize_document=True)
    result += proxy('/desktop/app/api/tokens', 'api/tokens', True)
    result += proxy('/desktop/app/', '')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    registry = catalog.load(args.catalog)
    snippet = render(registry, args.port)
    os.umask(0o077)
    args.out.mkdir(mode=0o700)
    with (args.out/'portal.conf').open('x') as out:
        out.write(snippet)
    with (args.out/'rate-limit.conf').open('x') as out:
        out.write('limit_req_zone $binary_remote_addr zone=guacamole_portal_auth:1m rate=6r/m;\n')
    print(json.dumps({'rendered': True, 'installed': False}))


if __name__ == '__main__':
    main()
