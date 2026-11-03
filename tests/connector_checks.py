"""A–D connector checks. No actual operator consent, credential or provider call."""
import copy
import http.client
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from core import network_guard as network
from core.contracts import Refusal, canonical, digest, strict_json, EXAMPLE, MODEL
from core.store import Store
from core.demo_host import DemoHost, ConsentRecords, DECISIONS
from core.terminal_credentials import TerminalCredentials
from core.meta_live import MetaHTTPS
from app import make_server
from connector_support import PTYPump, ControlledTransport, SYNTHETIC_SECRET, ALL_DECISIONS, wire
ROOT=Path(__file__).resolve().parents[1]
CHILD_ENV={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}

class ConnectorChecks(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.store=Store(self.root/'workspace',connector=True);self.pty=PTYPump()
        self.transport=ControlledTransport(self.store)
        self.host=DemoHost(self.store,self.root/'consents',ROOT,credentials=self.pty.credentials,
            transport_factory=lambda:self.transport,test_mode=True)
    def tearDown(self):
        self.pty.close();self.store.close();self.temp.cleanup()
    def ready(self):
        self.store.load_source();self.store.save(EXAMPLE)
        req=self.store.prepare('META_LIVE',digest(EXAMPLE))
        return req,self.host.preview(req)
    def execute(self,req,p,**kw):
        self.pty.arm();result=self.host.execute(req['id'],p['token'],ALL_DECISIONS,True,**kw)
        self.pty.finish();return result
    def refusal(self,fn,expected=None):
        with self.assertRaises(Refusal) as c:fn()
        if expected:self.assertEqual(c.exception.code,expected)
        return c.exception.code
    def test_A01_explicit_decisions_unknown_scope_offline_permit_and_cancel(self):
        req,p=self.ready()
        for decisions,immediate in [({},True),(dict(ALL_DECISIONS,risk=False),True),(ALL_DECISIONS,False),
                (dict(ALL_DECISIONS,scope='OLD_OFFLINE_PERMIT'),True)]:
            self.refusal(lambda:self.host.execute(req['id'],p['token'],decisions,immediate),'EXPLICIT_DECISIONS_REQUIRED')
        self.refusal(lambda:self.host.execute(req['id'],'old-offline-token',ALL_DECISIONS,True),'CONFIRMATION_TOKEN')
        self.host.records.cancel(req['id'],p['token'])
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'REQUEST_ALREADY_CONSUMED')
        self.assertEqual(self.store.view()['live_attempts'],0);self.assertEqual(self.transport.calls,0)
        self.assertFalse(select.select([self.pty.master],[],[],.02)[0])
    def test_A02_context_model_program_and_expiry_rejected_before_secret(self):
        req,p=self.ready()
        for key,value in [('model','other'),('schema','OFFLINE_SCOPE'),('program_manifest_sha','0'*64),('body_sha','0'*64)]:
            altered=dict(p['context'],**{key:value})
            with patch.object(self.host,'context',return_value=altered):
                self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'CONFIRMATION_CONTEXT_CHANGED')
        with patch('core.store.time.time',return_value=req['expires_at']+1):
            self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'REQUEST_EXPIRED_OR_CLOCK_ROLLBACK')
        with patch('core.store.time.time',return_value=req['created_at']-1):
            self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'REQUEST_EXPIRED_OR_CLOCK_ROLLBACK')
        self.assertEqual(self.transport.calls,0);self.assertEqual(self.store.view()['live_attempts'],0)
    def test_A03_double_click_and_independent_next_request(self):
        req,p=self.ready();entered=threading.Event();release=threading.Event();out=[]
        self.transport.effect=lambda:(entered.set(),release.wait(3))
        self.pty.arm()
        def go():
            try:out.append(self.host.execute(req['id'],p['token'],ALL_DECISIONS,True))
            except Exception as e:out.append(type(e).__name__)
        t=threading.Thread(target=go);t.start();self.assertTrue(entered.wait(3))
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'REQUEST_IN_FLIGHT')
        release.set();t.join(4);self.pty.finish();self.assertEqual(len(out),1);self.assertEqual(self.transport.calls,1)
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'REQUEST_REPLAY_OR_STALE')
        req2=self.store.prepare('META_LIVE',digest(EXAMPLE));p2=self.host.preview(req2)
        self.assertNotEqual(req2['id'],req['id']);self.assertEqual(self.transport.calls,1)
        self.transport.effect=None;self.execute(req2,p2);self.assertEqual(self.transport.calls,2)
        grants=self.host.records.load(req2['id'])['grants'];self.assertEqual(len(grants),6)
        self.assertEqual(len({g['event_id'] for g in grants.values()}),6)
        self.assertTrue(all(g['actor']=='SYNTHETIC_TEST_OPERATOR' for g in grants.values()))
    def test_A04_two_process_consumption_and_workspace_copy(self):
        req,p=self.ready();packet=self.root/'packet.json';packet.write_bytes(canonical(p))
        child="""import sys,json,time
sys.path.insert(0,sys.argv[1])
from core import network_guard as n
n.configure_test()
from core.demo_host import ConsentRecords,DECISIONS
from core.contracts import Refusal
p=json.load(open(sys.argv[3]));time.sleep(.15)
try:
 ConsentRecords(sys.argv[2]).consume(p['context'],p['token'],{k:True for k in DECISIONS},True);print('CONSUMED')
except Refusal as e:print(e.code)
"""
        args=[sys.executable,'-I','-B','-S','-c',child,str(ROOT),str(self.root/'consents'),str(packet)]
        procs=[subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=CHILD_ENV) for _ in range(2)]
        outputs=[x.communicate(timeout=5)[0].decode().strip() for x in procs]
        self.assertEqual(outputs.count('CONSUMED'),1);self.assertIn('REQUEST_ALREADY_CONSUMED',outputs)
        shutil.copytree(self.root/'workspace',self.root/'copy')
        copied=Store(self.root/'copy',connector=True)
        try:
            self.refusal(lambda:DemoHost(copied,self.root/'different-consents',ROOT,
                credentials=self.pty.credentials,transport_factory=lambda:self.transport,test_mode=True),'CONSENT_REGISTRY_MISMATCH')
        finally:copied.close()
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'REQUEST_ALREADY_CONSUMED')
        self.assertEqual(self.transport.calls,0)
    def test_A05_persistence_failure_corruption_and_missing_record_fail_closed(self):
        req,p=self.ready()
        with patch.object(self.host.records,'write',side_effect=Refusal('CONSENT_PERSISTENCE_FAILED')):
            self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'CONSENT_PERSISTENCE_FAILED')
        self.assertTrue(self.host.records.marker(req['id']).exists())
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'REQUEST_ALREADY_CONSUMED')
        path=self.host.records.path(req['id']);path.write_bytes(b'{bad')
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True))
        path.unlink();self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'CONSENT_RECORD_MISSING_OR_UNSAFE')
        self.assertEqual(self.transport.calls,0);self.assertEqual(self.store.view()['live_attempts'],0)
    def test_A06_crash_restart_and_timeout_never_replay(self):
        req,p=self.ready();self.host.records.consume(p['context'],p['token'],ALL_DECISIONS,True)
        self.store.begin(req['id'],True,'META_LIVE');self.store.close()
        self.store=Store(self.root/'workspace',connector=True)
        self.assertEqual(self.store.request(req['id'])['status'],'UNKNOWN_NO_RETRY')
        self.host.store=self.store
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'REQUEST_REPLAY_OR_STALE')
        req2=self.store.prepare('META_LIVE',digest(EXAMPLE));p2=self.host.preview(req2)
        self.transport=ControlledTransport(self.store,failure=TimeoutError('DO_NOT_SAVE_EXCEPTION_SECRET'))
        self.pty.arm();self.refusal(lambda:self.host.execute(req2['id'],p2['token'],ALL_DECISIONS,True),'CONNECTOR_EXECUTION_UNKNOWN');self.pty.finish()
        self.assertEqual(self.transport.calls,1);self.assertEqual(self.host.records.load(req2['id'])['phase'],'UNKNOWN_NO_RETRY')
        self.assertIsNone(self.store.request(req2['id'])['outcome']['usage'])
        self.assertNotIn('DO_NOT_SAVE_EXCEPTION_SECRET',(self.root/'workspace/workspace.json').read_text())
    def test_A07_completion_record_failure_never_exposes_current(self):
        req,p=self.ready();self.pty.arm()
        with patch.object(self.host.records,'complete',side_effect=Refusal('CONSENT_PERSISTENCE_FAILED')):
            self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'CONSENT_PERSISTENCE_FAILED')
        self.pty.finish();self.assertEqual(self.transport.calls,1)
        self.assertFalse(self.store.view()['reviews'])
        self.assertEqual(self.store.request(req['id'])['status'],'UNKNOWN_NO_RETRY')
        self.assertEqual(self.host.records.load(req['id'])['phase'],'CONSUMED_UNKNOWN')
        self.assertIsNotNone(self.store.request(req['id'])['outcome']['raw_response_sha'])
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'REQUEST_REPLAY_OR_STALE')
    def test_B01_actual_pty_no_echo_and_restoration_success(self):
        self.pty.arm();value=self.pty.credentials.acquire(threading.Event(),lambda:None)
        self.assertEqual(value,SYNTHETIC_SECRET);value[:]=b'\0'*len(value);self.pty.finish()
    def test_B02_actual_pty_cancel_eof_timeout_format_and_stop(self):
        for data,expected in [(b'\x03','CREDENTIAL_CANCELLED'),(b'\x1b','CREDENTIAL_CANCELLED'),
                (b'\x04','CREDENTIAL_EOF'),(b'bad\n','CREDENTIAL_FORMAT'),(b'\xff','CREDENTIAL_FORMAT'),(None,'CREDENTIAL_TIMEOUT')]:
            with self.subTest(expected=expected,data=data):
                self.pty.credentials.timeout=.15;self.pty.arm(data)
                self.refusal(lambda:self.pty.credentials.acquire(threading.Event(),lambda:None),expected);self.pty.finish()
        event=threading.Event();self.pty.arm(None,signal=event.set)
        self.refusal(lambda:self.pty.credentials.acquire(event,lambda:None),'CREDENTIAL_CANCELLED');self.pty.finish()
    def test_B03_real_signal_interrupt_restores_tty_no_fallback(self):
        child="""import os,sys,threading
sys.path.insert(0,sys.argv[1])
from core import network_guard as n
n.configure_test()
from core.terminal_credentials import TerminalCredentials
from core.contracts import Refusal
try:TerminalCredentials(2,lambda:os.dup(int(sys.argv[2]))).acquire(threading.Event(),lambda:None)
except Refusal as e:print(e.code)
"""
        proc=subprocess.Popen([sys.executable,'-I','-B','-S','-c',child,str(ROOT),str(self.pty.slave)],
            pass_fds=(self.pty.slave,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=CHILD_ENV)
        self.pty.arm(None,signal=lambda:proc.send_signal(signal.SIGINT))
        out,err=proc.communicate(timeout=5);self.assertIn(b'CREDENTIAL_CANCELLED',out);self.assertEqual(err,b'');self.pty.finish()
        read,write=os.pipe()
        try:
            credentials=TerminalCredentials(.1,lambda:os.dup(read))
            self.refusal(lambda:credentials.acquire(threading.Event(),lambda:None),'SECURE_TTY_REQUIRED')
        finally:os.close(read);os.close(write)
    def test_B04_stop_during_real_pty_input_zero_transport(self):
        req,p=self.ready();self.pty.arm(None,signal=self.host.stop)
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'CREDENTIAL_CANCELLED');self.pty.finish()
        self.assertEqual(self.transport.calls,0);self.assertTrue(self.host.records.marker(req['id']).exists())
    def test_B05_secret_echo_and_escaped_invalid_answer_not_persisted(self):
        req,p=self.ready()
        def mutate(reply):
            inner=strict_json(reply['output'][0]['content'][0]['text'].encode())
            inner['unexpected']=SYNTHETIC_SECRET.decode()
            encoded=''.join('\\u%04x'%c for c in SYNTHETIC_SECRET)
            reply['output'][0]['content'][0]['text']=canonical(inner).decode().replace(SYNTHETIC_SECRET.decode(),encoded)
        self.transport.mutation=mutate;self.pty.arm()
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'SECRET_ECHO_REJECTED');self.pty.finish()
        self.assertIsNone(self.store.request(req['id'])['outcome']['raw_response_sha'])
        for f in self.root.rglob('*'):
            if f.is_file():self.assertNotIn(SYNTHETIC_SECRET,f.read_bytes())
        self.assertEqual(set(self.transport.secret_ref),{0})
    def test_B06_default_dev_tty_path_with_synthetic_controlling_terminal(self):
        import pty
        child="""import os,sys,threading,termios
sys.path.insert(0,sys.argv[1])
from core import network_guard as n
n.configure_test()
from core.terminal_credentials import TerminalCredentials
fd=os.open('/dev/tty',os.O_RDWR);before=termios.tcgetattr(fd)
value=TerminalCredentials(1).acquire(threading.Event(),lambda:None)
print('SYNTHETIC_TTY_BYTES',len(value),'RESTORED',before==termios.tcgetattr(fd),flush=True)
value[:]=bytes(len(value));os.close(fd)
"""
        pid,master=pty.fork()
        if pid==0:
            os.execve(sys.executable,[sys.executable,'-I','-B','-S','-c',child,str(ROOT)],CHILD_ENV)
        transcript=bytearray();sent=False;status=None;deadline=time.monotonic()+4
        try:
            while time.monotonic()<deadline:
                if select.select([master],[],[],.05)[0]:
                    try:data=os.read(master,8192)
                    except OSError:data=b''
                    transcript.extend(data)
                    if not sent and b'bounded timeout): ' in transcript:
                        os.write(master,SYNTHETIC_SECRET+b'\n');sent=True
                done,status_now=os.waitpid(pid,os.WNOHANG)
                if done:status=status_now;break
            self.assertIsNotNone(status,'CONTROLLED_TTY_CHILD_TIMEOUT')
            self.assertEqual(os.waitstatus_to_exitcode(status),0,transcript.decode(errors='replace'))
            self.assertIn(b'RESTORED True',transcript);self.assertNotIn(SYNTHETIC_SECRET,transcript)
        finally:
            if status is None:
                os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
            os.close(master)
    def test_C01_full_http_flow_cancel_synthetic_success_quotes_and_stale(self):
        server=make_server(self.store,demo_host=self.host);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        csrf=''
        def call(path,body=None):
            c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            c.request('GET' if body is None else 'POST',path,body=canonical(body) if body is not None else None,
                headers={'Content-Type':'application/json','X-Muse-CSRF':csrf})
            r=c.getresponse();raw=r.read();status=r.status;c.close();return status,strict_json(raw)
        try:
            _,s=call('/api/state');csrf=s['csrf'];self.assertEqual(s['connector_mode'],'CONTROLLED_TEST')
            call('/api/load',{});call('/api/save',{'text':EXAMPLE})
            _,p=call('/api/prepare',{'mode':'META_LIVE','saved_sha':digest(EXAMPLE)});r=p['result']
            self.assertEqual(call('/api/live/cancel',{'request_id':r['id'],'token':r['confirmation']['token']})[0],200)
            self.assertEqual(self.transport.calls,0)
            _,p=call('/api/prepare',{'mode':'META_LIVE','saved_sha':digest(EXAMPLE)});r=p['result']
            self.assertEqual(r['confirmation']['context']['binding']['draft_sha'],digest(EXAMPLE))
            self.assertEqual(call('/api/live/execute',{'grant':{'authorized':True}})[0],409)
            self.pty.arm();status,result=call('/api/live/execute',{'request_id':r['id'],'token':r['confirmation']['token'],
                'decisions':ALL_DECISIONS,'immediate':True});self.pty.finish();self.assertEqual(status,200,result)
            review=result['state']['reviews'][0];self.assertEqual(len(review['review']['findings']),4)
            self.assertEqual(review['receipt']['provenance'],'SYNTHETIC_PREFLIGHT_TRANSPORT')
            self.assertFalse(result['state']['real_meta_review_completed']);self.assertEqual(self.transport.calls,1)
            self.assertEqual(result['state']['requests'][-1]['outcome']['provenance'],'SYNTHETIC_PREFLIGHT_TRANSPORT')
            _,result=call('/api/save',{'text':'The Larch repair room has four worktables.'})
            self.assertEqual(result['state']['reviews'][0]['status'],'STALE')
            call('/api/stop',{});self.assertTrue(self.host.cancelled.is_set())
        finally:server.shutdown();server.server_close();thread.join(2)
    def test_C02_http_failure_is_a_call_usage_unknown_not_zero(self):
        req,p=self.ready();self.transport.status=500;self.transport.mutation=lambda x:x.pop('usage')
        self.pty.arm();self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'HTTP_STATUS_REJECTED');self.pty.finish()
        outcome=self.store.request(req['id'])['outcome'];self.assertEqual(outcome['transport']['http_status'],500)
        self.assertIsNone(outcome['usage']);self.assertIsNotNone(outcome['raw_response_sha'])
        self.assertEqual(self.transport.calls,1);self.assertFalse(self.store.view()['reviews'])
    def test_C03_invalid_quote_retains_response_and_reported_usage(self):
        req,p=self.ready()
        def mutate(x):
            review=strict_json(x['output'][0]['content'][0]['text'].encode());review['findings'][0]['citations'][0]['quote']='invented'
            x['output'][0]['content'][0]['text']=canonical(review).decode()
        self.transport.mutation=mutate;self.pty.arm()
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'QUOTE_MISMATCH');self.pty.finish()
        outcome=self.store.request(req['id'])['outcome'];self.assertEqual(outcome['usage']['total_tokens'],500)
        self.assertEqual(outcome['transport']['phase'],'RESPONSE_BODY_RECEIVED');self.assertFalse(self.store.view()['reviews'])
    def test_C04_inflight_save_keeps_safe_reply_usage_only_as_history(self):
        req,p=self.ready();self.transport.effect=lambda:self.store.save('Human changed the saved draft.')
        result=self.execute(req,p);self.assertFalse(result['current'])
        self.assertEqual(self.store.view()['reviews'][0]['status'],'STALE')
        self.assertEqual(self.store.request(req['id'])['outcome']['usage']['total_tokens'],500)
        self.store.save(EXAMPLE);self.assertEqual(self.store.view()['reviews'][0]['status'],'STALE')
        req2=self.store.prepare('META_LIVE',digest(EXAMPLE));p2=self.host.preview(req2)
        original=self.host.context
        self.transport.effect=lambda:setattr(self.host,'context',lambda r:dict(original(r),program_manifest_sha='0'*64))
        result=self.execute(req2,p2);self.assertFalse(result['current'])
        self.assertEqual(self.store.view()['reviews'][-1]['status'],'STALE')
    def test_C05_stop_policy_source_and_program_binding(self):
        req,p=self.ready();self.store._change(lambda s:s.update(source_epoch=s['source_epoch']+1))
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'CONTEXT_STALE')
        req=self.store.prepare('META_LIVE',digest(EXAMPLE));p=self.host.preview(req)
        with patch('core.store.POLICY','Changed policy'):
            self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'CONTEXT_STALE')
        self.transport.effect=lambda:(self.store.stop(),self.host.stop())
        result=self.execute(req,p);self.assertFalse(result['current']);self.assertEqual(self.store.view()['reviews'][0]['status'],'STALE')
        self.assertEqual(self.transport.calls,1)
    def test_D01_network_fence_and_no_real_credentials_on_test_transport(self):
        self.refusal(lambda:socket.getaddrinfo('api.meta.ai',443),'NETWORK_DESTINATION_REJECTED')
        with socket.socket() as sock:self.refusal(lambda:sock.connect(('192.0.2.1',443)),'NETWORK_DESTINATION_REJECTED')
        self.refusal(network.configure_live,'TEST_NETWORK_LOCKED')
        self.refusal(lambda:DemoHost(self.store,self.root/'consents',ROOT,credentials=self.pty.credentials),'REAL_CONNECTOR_CONFIGURATION')
        self.refusal(lambda:MetaHTTPS().send(b'{}',bytearray(SYNTHETIC_SECRET),lambda:None),'SYNTHETIC_SECRET_ON_REAL_TRANSPORT')
    def test_D02_real_adapter_fixed_tls_destination_no_redirect_or_retry(self):
        req,p=self.ready();calls=[]
        class Reply:
            status=302
            def getheader(self,k,default=None):return {'Content-Type':'application/json','Content-Length':'2','Location':'https://other.invalid'}.get(k,default)
            def read1(self,n):
                if getattr(self,'read',False):return b''
                self.read=True;return b'{}'
        class Connection:
            def __init__(self,*args,**kw):
                calls.append(('connection',args,kw['context'].check_hostname,kw['context'].verify_mode))
            def request(self,*args,**kw):calls.append(('post',args[0],args[1],digest(kw['body'])))
            def getresponse(self):return Reply()
            def close(self):pass
        t=MetaHTTPS();t.fixed_destination_guard=True
        with patch('core.meta_live.http.client.HTTPSConnection',Connection):
            status,raw=t.send(req['body'].encode(),bytearray(b'fake-protocol-test-not-a-secret'),lambda:None)
        self.assertEqual(status,302);self.assertEqual(len(calls),2);self.assertEqual(calls[0][1],('api.meta.ai',443))
        self.assertTrue(calls[0][2]);self.assertEqual(calls[0][3],2);self.assertEqual(calls[1][1:3],('POST','/v1/responses'))
    def test_D03_store_failure_keeps_consumption_and_restart_refusal(self):
        req,p=self.ready()
        with patch.object(self.store,'_persist',side_effect=OSError('synthetic disk error')):
            self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'PERSISTENCE_FAULT_STOPPED')
        self.assertTrue(self.host.records.marker(req['id']).exists());self.assertEqual(self.transport.calls,0)
        self.store.close();self.store=Store(self.root/'workspace',connector=True);self.host.store=self.store
        self.refusal(lambda:self.host.execute(req['id'],p['token'],ALL_DECISIONS,True),'REQUEST_REPLAY_OR_STALE')
    def test_D04_no_key_cold_start_readme_live_launcher(self):
        clean=self.root/'clean';clean.mkdir()
        manifest=json.loads((ROOT/'MANIFEST.json').read_text())
        for name in [*manifest['files'],'MANIFEST.json']:
            dest=clean/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest)
        checked=subprocess.run([sys.executable,'-I','-B','-S','verify.py'],cwd=clean,env=CHILD_ENV,capture_output=True,timeout=5)
        self.assertEqual(checked.returncode,0,checked.stderr)
        proc=subprocess.Popen([sys.executable,'-I','-B','-S','live.py'],cwd=clean,env=CHILD_ENV,
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            ready,_,_=select.select([proc.stdout],[],[],5);self.assertTrue(ready)
            line=proc.stdout.readline();boot=json.loads(line);self.assertEqual(boot['live_authorization'],'PENDING')
            port=int(boot['url'].rsplit(':',1)[1]);conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
            conn.request('GET','/api/state');res=conn.getresponse();state=strict_json(res.read());conn.close()
            self.assertEqual(state['live_attempts'],0);self.assertEqual(state['connector_mode'],'META_LIVE')
            self.assertFalse(state['real_meta_review_completed']);self.assertEqual(state['formal_gate'],'OFF')
            self.assertFalse(list((clean/'.muse-consents').glob('*.spent')))
            proc.send_signal(signal.SIGINT);out,err=proc.communicate(timeout=5)
            self.assertIn(b'"stopped":true',out);self.assertEqual(err,b'')
        finally:
            if proc.poll() is None:proc.kill();proc.communicate()
