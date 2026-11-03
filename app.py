"""Loopback editor; independent demo Live requires explicit per-request local consent."""
import argparse
import json
import secrets
import sys
import threading
from socketserver import TCPServer
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from core.contracts import Refusal, EXAMPLE, canonical, strict_json, fields, require
from core.store import Store
from core.meta_live import run_offline, run_live, safe_code


def make_server(store, port=0, authority=None, credentials=None, demo_host=None):
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
                    data.update(csrf=token, example=EXAMPLE, live_host_connected=demo_host is not None,
                        connector_mode=('CONTROLLED_TEST' if demo_host.test_mode else 'META_LIVE') if demo_host else 'OFFLINE_DEMO',
                        multiple_live_requests=bool(demo_host))
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
                    if body['mode']=='META_LIVE' and demo_host is not None:
                        result['confirmation']=demo_host.preview(result)
                elif self.path == '/api/run':
                    fields(body, ['request_id', 'confirmed'])
                    req = store.request(body['request_id'])
                    if req['mode'] == 'OFFLINE_DEMO':
                        run_offline(store, req['id'], body['confirmed'])
                    else:
                        run_live(store, req['id'], body['confirmed'], authority, credentials)
                elif self.path == '/api/live/execute':
                    fields(body,['request_id','token','decisions','immediate'])
                    require(demo_host is not None,'LIVE_AUTHORIZATION_PENDING')
                    result=demo_host.execute(body['request_id'],body['token'],body['decisions'],body['immediate'])
                elif self.path == '/api/live/cancel':
                    fields(body,['request_id','token'])
                    require(demo_host is not None,'LIVE_AUTHORIZATION_PENDING')
                    demo_host.records.cancel(body['request_id'],body['token'])
                elif self.path == '/api/stop':
                    fields(body, []); store.stop()
                    if demo_host is not None:demo_host.stop()
                else:
                    raise Refusal('ACTION_REJECTED')
                visible = store.view()
                visible.update(live_host_connected=demo_host is not None,
                    connector_mode=('CONTROLLED_TEST' if demo_host.test_mode else 'META_LIVE') if demo_host else 'OFFLINE_DEMO',
                    multiple_live_requests=bool(demo_host))
                self.reply(200, canonical({'state': visible, 'result': result}))
            except Exception as exc:
                self.reply(409, canonical({'error': safe_code(exc)}))

    class LocalServer(ThreadingHTTPServer):
        def server_bind(self):
            # No reverse-DNS lookup is necessary for a fixed loopback UI.
            TCPServer.server_bind(self)
            self.server_name='127.0.0.1';self.server_port=self.server_address[1]
    server = LocalServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    return server


def main(live=False):
    require(sys.flags.isolated and sys.dont_write_bytecode, 'USE_ISOLATED_PYTHON')
    from verify import verify
    verify(ROOT)
    from core import network_guard
    if live:network_guard.configure_live()
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--state', default='.muse-p2-workspace' if live else '.muse-local')
    if live:
        parser.add_argument('--consents',default='.muse-consents')
        parser.add_argument('--account-reference',default='my-meta-account')
    args = parser.parse_args()
    require(0 <= args.port <= 65535, 'PORT_RANGE')
    store = Store(args.state,connector=live)
    host=None
    if live:
        from core.demo_host import DemoHost
        host=DemoHost(store,args.consents,ROOT,args.account_reference)
    server = make_server(store, args.port,demo_host=host)
    print(json.dumps({'url': 'http://127.0.0.1:'+str(server.server_port), 'mode': 'META_LIVE_READY_FOR_LOCAL_CONFIRMATION' if live else 'OFFLINE_DEMO',
                      'formal_gate': 'OFF', 'live_authorization': 'PENDING'}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        if host is not None:host.shutdown()
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
