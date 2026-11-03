"""Loopback-only new MUSE core. No CLI flag can open formal Live authority."""
import argparse
import json
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from core.contracts import Refusal, EXAMPLE, canonical, strict_json, fields, require
from core.store import Store
from core.meta_live import run_offline, run_live, safe_code


def make_server(store, port=0, authority=None, credentials=None):
    token = secrets.token_urlsafe(32)
    assets = {'/': ('web/index.html', 'text/html; charset=utf-8'),
              '/app.js': ('web/app.js', 'text/javascript; charset=utf-8'),
              '/style.css': ('web/style.css', 'text/css; charset=utf-8')}

    class Handler(BaseHTTPRequestHandler):
        server_version = 'MUSECoreR1'
        def log_message(self, *args):
            pass

        def reply(self, status, data, mime='application/json; charset=utf-8'):
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def origin(self, post=False):
            expected = '127.0.0.1:'+str(self.server.server_port)
            require(self.headers.get('Host') == expected, 'HOST_REJECTED')
            # A normal address-bar/link navigation may originate outside the app.
            # Static assets contain no session data or token; API routes stay strict.
            if post or self.path not in assets:
                require(self.headers.get('Origin') in (None, 'http://'+expected), 'ORIGIN_REJECTED')
                require(self.headers.get('Sec-Fetch-Site') not in ('cross-site',), 'ORIGIN_REJECTED')
            if post:
                require(secrets.compare_digest(self.headers.get('X-Muse-CSRF', ''), token), 'CSRF_REJECTED')

        def do_GET(self):
            try:
                self.origin()
                if self.path == '/api/state':
                    data = store.view()
                    data.update(csrf=token, example=EXAMPLE, live_host_connected=authority is not None and credentials is not None)
                    self.reply(200, canonical(data))
                elif self.path in assets:
                    file, mime = assets[self.path]
                    self.reply(200, (ROOT/file).read_bytes(), mime)
                else:
                    self.reply(404, canonical({'error': 'NOT_FOUND'}))
            except Exception as exc:
                self.reply(403, canonical({'error': safe_code(exc)}))

        def do_POST(self):
            try:
                self.origin(True)
                require(self.headers.get('Transfer-Encoding') is None, 'TRANSFER_ENCODING_REJECTED')
                require(self.headers.get('Content-Type', '').split(';')[0] == 'application/json', 'CONTENT_TYPE')
                lengths = self.headers.get_all('Content-Length') or []
                require(len(lengths) == 1 and lengths[0].isdigit() and 0 < int(lengths[0]) <= 32768, 'BODY_SIZE')
                self.connection.settimeout(5)
                raw = self.rfile.read(int(lengths[0]))
                require(len(raw) == int(lengths[0]), 'BODY_INCOMPLETE')
                body = strict_json(raw, 32768)
                result = None
                if self.path == '/api/load':
                    fields(body, []); store.load_source()
                elif self.path == '/api/save':
                    fields(body, ['text']); store.save(body['text'])
                elif self.path == '/api/prepare':
                    fields(body, ['mode', 'saved_sha'])
                    result = store.prepare(body['mode'], body['saved_sha'])
                elif self.path == '/api/run':
                    fields(body, ['request_id', 'confirmed'])
                    req = store.request(body['request_id'])
                    if req['mode'] == 'OFFLINE_DEMO':
                        run_offline(store, req['id'], body['confirmed'])
                    else:
                        run_live(store, req['id'], body['confirmed'], authority, credentials)
                elif self.path == '/api/stop':
                    fields(body, []); store.stop()
                else:
                    raise Refusal('ACTION_REJECTED')
                visible = store.view()
                visible['live_host_connected'] = authority is not None and credentials is not None
                self.reply(200, canonical({'state': visible, 'result': result}))
            except Exception as exc:
                self.reply(409, canonical({'error': safe_code(exc)}))

    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    return server


def main():
    require(sys.flags.isolated and sys.dont_write_bytecode, 'USE_ISOLATED_PYTHON')
    from verify import verify
    verify(ROOT)
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--state', default='.muse-local')
    args = parser.parse_args()
    require(0 <= args.port <= 65535, 'PORT_RANGE')
    store = Store(args.state)
    server = make_server(store, args.port)
    print(json.dumps({'url': 'http://127.0.0.1:'+str(server.server_port), 'mode': 'OFFLINE_DEMO',
                      'formal_gate': 'OFF', 'live_authorization': 'PENDING'}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        try:
            store.stop('NORMAL_STOP')
        finally:
            store.close()
        print('{"stopped":true,"automatic_retry":false}', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'error': safe_code(exc)}), flush=True)
        raise SystemExit(1)
