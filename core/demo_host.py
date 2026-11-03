"""Versioned local-operator demo connector; not an organizational authority or billing ledger."""
import base64
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from .contracts import Refusal, MODEL, ENDPOINT, canonical, digest, strict_json, require, fields
from .meta_live import MetaHTTPS, parse_response, no_secret_in_decoded, MAX_REPLY
from .terminal_credentials import TerminalCredentials
from . import network_guard as network

SCHEMA='MUSE_DEMO_LIVE_SCOPE_2'
DECISIONS={'b1','risk','data_egress','budget_once','final_dispatch'}


def code(exc):
    value=exc.code if isinstance(exc,Refusal) else 'CONNECTOR_EXECUTION_UNKNOWN'
    return value if re.fullmatch('[A-Z0-9_]{1,80}',value) else 'CONNECTOR_EXECUTION_UNKNOWN'

def sync_dir(root):
    fd=os.open(str(root),os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def read_record(path):
    try:fd=os.open(str(path),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    except OSError:raise Refusal('CONSENT_RECORD_MISSING_OR_UNSAFE') from None
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and
            stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=131072,'CONSENT_RECORD_UNSAFE')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(131073)
        return strict_json(raw,131072)
    finally:os.close(fd)

def write_new(path,value):
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as f:f.write(canonical(value));f.flush();os.fsync(f.fileno())
    sync_dir(path.parent)

class ConsentRecords:
    def __init__(self,directory):
        self.root=Path(directory).absolute();self.mutex=threading.RLock()
        if not self.root.exists():
            self.root.mkdir(mode=0o700)
            write_new(self.root/'anchor.json',{'schema':SCHEMA,'id':uuid.uuid4().hex})
            write_new(self.root/'lock',{})
        require(not self.root.is_symlink() and self.root.stat().st_uid==os.getuid() and
            stat.S_IMODE(self.root.stat().st_mode)==0o700,'CONSENT_RECORD_UNSAFE')
        anchor=read_record(self.root/'anchor.json');fields(anchor,['schema','id'])
        require(anchor['schema']==SCHEMA and re.fullmatch('[a-f0-9]{32}',anchor['id']),'CONSENT_RECORD_UNSAFE')
        self.id=anchor['id'];read_record(self.root/'lock')
    @contextmanager
    def lock(self):
        with self.mutex:
            read_record(self.root/'lock')
            fd=os.open(str(self.root/'lock'),os.O_RDWR|getattr(os,'O_NOFOLLOW',0));deadline=time.monotonic()+1
            try:
                while True:
                    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                    except BlockingIOError:
                        require(time.monotonic()<deadline,'CONSENT_LOCK_TIMEOUT');time.sleep(.005)
                yield
            finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
    def path(self,rid):
        require(type(rid) is str and re.fullmatch('muse-r1-[a-f0-9]{32}',rid),'REQUEST_ID')
        return self.root/(rid+'.json')
    def marker(self,rid):return self.root/(rid+'.spent')
    def load(self,rid):
        r=read_record(self.path(rid));fields(r,['schema','registry_id','context','token','phase','grants','outcome'])
        require(r['schema']==SCHEMA and r['registry_id']==self.id and r['context']['request_id']==rid and
            r['phase'] in ('PREVIEWED','CANCELLED','CONSUMED_UNKNOWN','COMPLETED','REJECTED','UNKNOWN_NO_RETRY'),'CONSENT_RECORD_UNSAFE')
        spent=self.marker(rid)
        if r['phase'] in ('PREVIEWED','CANCELLED'):
            require(not spent.exists() and not spent.is_symlink(),'REQUEST_ALREADY_CONSUMED')
        else:
            marker=read_record(spent)
            require(marker=={'context_sha':digest(canonical(r['context'])),'grants':r['grants'],'registry_id':self.id},'CONSENT_RECORD_UNSAFE')
        return r
    def write(self,rid,r):
        fd,name=tempfile.mkstemp(prefix='.atomic-',dir=str(self.root))
        try:
            with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(canonical(r));f.flush();os.fsync(f.fileno())
            os.replace(name,str(self.path(rid)));sync_dir(self.root)
        except Exception:raise Refusal('CONSENT_PERSISTENCE_FAILED') from None
        finally:
            if os.path.exists(name):os.unlink(name)
    def preview(self,context):
        rid=context['request_id'];token=secrets.token_urlsafe(32)
        r={'schema':SCHEMA,'registry_id':self.id,'context':context,'token':token,'phase':'PREVIEWED','grants':None,'outcome':None}
        with self.lock():
            require(len(list(self.root.glob('muse-r1-*.json')))<256,'CONSENT_RECORD_LIMIT')
            try:write_new(self.path(rid),r)
            except FileExistsError:raise Refusal('REQUEST_ALREADY_REGISTERED') from None
        return token
    def consume(self,context,token,decisions,immediate):
        require(type(decisions) is dict and set(decisions)==DECISIONS and
            all(v is True for v in decisions.values()) and immediate is True,'EXPLICIT_DECISIONS_REQUIRED')
        rid=context['request_id']
        with self.lock():
            r=self.load(rid)
            require(r['phase']=='PREVIEWED','REQUEST_ALREADY_CONSUMED')
            require(type(token) is str and secrets.compare_digest(r['token'],token),'CONFIRMATION_TOKEN')
            require(r['context']==context,'CONFIRMATION_CONTEXT_CHANGED')
            require(context['created_at']<=time.time()<context['expires_at'],'CONFIRMATION_EXPIRED')
            actor='SYNTHETIC_TEST_OPERATOR' if context['execution']=='CONTROLLED_TEST' else 'LOCAL_OPERATOR'
            grants={k:{'accepted':True,'event_id':uuid.uuid4().hex,'actor':actor,'time':time.time()}
                for k in ['B1_DEMO_USE','RISK_ACCEPTANCE','DATA_EGRESS','BUDGET_ONCE','FINAL_DISPATCH','IMMEDIATE_HUMAN_CONFIRMATION']}
            marker={'context_sha':digest(canonical(context)),'grants':grants,'registry_id':self.id}
            try:write_new(self.marker(rid),marker)
            except FileExistsError:raise Refusal('REQUEST_ALREADY_CONSUMED') from None
            r.update(phase='CONSUMED_UNKNOWN',grants=grants)
            self.write(rid,r)
            return digest(canonical(marker))
    def revalidate(self,context):
        with self.lock():
            r=self.load(context['request_id'])
            require(r['phase']=='CONSUMED_UNKNOWN' and r['context']==context,'CONSENT_NOT_CURRENT')
            require(context['created_at']<=time.time()<context['expires_at'],'CONFIRMATION_EXPIRED')
    def complete(self,rid,phase,outcome):
        require(phase in ('COMPLETED','REJECTED','UNKNOWN_NO_RETRY'),'CONSENT_PHASE')
        with self.lock():
            r=self.load(rid);require(r['phase']=='CONSUMED_UNKNOWN','CONSENT_NOT_CURRENT')
            r.update(phase=phase,outcome=outcome);self.write(rid,r)
    def cancel(self,rid,token):
        with self.lock():
            r=self.load(rid)
            require(type(token) is str and secrets.compare_digest(r['token'],token),'CONFIRMATION_TOKEN')
            require(r['phase']=='PREVIEWED','REQUEST_ALREADY_CONSUMED')
            r['phase']='CANCELLED';self.write(rid,r)


def known_usage(value):
    u=value.get('usage') if type(value) is dict else None
    if type(u) is not dict:return None
    keys=('input_tokens','output_tokens','total_tokens')
    if not all(type(u.get(k)) is int and u[k]>=0 for k in keys):return None
    return {**{k:u[k] for k in keys},'status':'REPORTED_UNRECONCILED' if u['input_tokens']+u['output_tokens']==u['total_tokens'] else 'REPORTED_INCONSISTENT'}

class DemoHost:
    def __init__(self,store,records,program_root,account_reference='my-meta-account',credentials=None,
                 transport_factory=None,test_mode=False):
        require(store.connector,'CONNECTOR_WORKSPACE_REQUIRED')
        require(type(account_reference) is str and re.fullmatch('[A-Za-z0-9_-]{1,64}',account_reference),'ACCOUNT_REFERENCE')
        self.store=store;self.records=ConsentRecords(records);self.program_root=Path(program_root)
        self.store.bind_connector(self.records.id)
        self.account_reference=account_reference;self.test_mode=test_mode
        self.credentials=credentials or TerminalCredentials()
        require(type(self.credentials) is TerminalCredentials,'CREDENTIAL_CHANNEL_REQUIRED')
        if test_mode:
            require(network.test_locked() and transport_factory is not None,'TEST_NETWORK_LOCK_REQUIRED')
        else:
            require(transport_factory is None and self.credentials.default_terminal,'REAL_CONNECTOR_CONFIGURATION')
        self.transport_factory=transport_factory or MetaHTTPS
        self.active=threading.Lock();self.cancelled=threading.Event();self.done=threading.Event();self.done.set()
    def program_sha(self):
        from verify import verify
        verify(self.program_root)
        return digest((self.program_root/'MANIFEST.json').read_bytes())
    def context(self,req):
        return {'schema':SCHEMA,'purpose':'DEMO_ONLY','execution':'CONTROLLED_TEST' if self.test_mode else 'META_HTTPS',
            'request_id':req['id'],'body_sha':req['body_sha'],'body_bytes':req['body_bytes'],'binding':req['binding'],
            'model':MODEL,'endpoint':ENDPOINT,'program_manifest_sha':self.program_sha(),
            'account_reference':self.account_reference,'maximum_attempts':1,'risk_micro_usd':100000,
            'risk_is_provider_cap':False,'created_at':req['created_at'],'expires_at':req['expires_at']}
    def preview(self,req):
        require(req['mode']=='META_LIVE','REQUEST_MODE');self.store.check_current(req)
        context=self.context(req);token=self.records.preview(context)
        return {'context':context,'token':token}
    def stop(self):self.cancelled.set()
    def shutdown(self):self.stop();self.done.wait(2)
    def execute(self,rid,token,decisions,immediate):
        require(self.active.acquire(False),'REQUEST_IN_FLIGHT');self.done.clear()
        req=None;consumed=False;started=False;secret=None;transport=None;raw=None;safe_raw=None;usage=None
        trace={'phase':'NOT_STARTED','http_status':None};validation='NOT_RUN';result_written=False
        provenance='SYNTHETIC_PREFLIGHT_TRANSPORT' if self.test_mode else 'REAL_META_RESPONSE'
        try:
            require(not self.cancelled.is_set(),'WORKSPACE_STOPPED')
            req=self.store.request(rid);self.store.check_current(req)
            require(req['status']=='PREPARED','REQUEST_REPLAY_OR_STALE')
            context=self.context(req)
            scope_sha=self.records.consume(context,token,decisions,immediate);consumed=True
            req,draft=self.store.begin(rid,True,'META_LIVE');started=True
            def before_send():
                require(not self.cancelled.is_set(),'WORKSPACE_STOPPED')
                self.store.check_current(req);self.records.revalidate(context)
                require(self.context(req)==context,'CONFIRMATION_CONTEXT_CHANGED')
            before_send();secret=self.credentials.acquire(self.cancelled,before_send);before_send()
            transport=self.transport_factory()
            if self.test_mode:require(type(transport) is not MetaHTTPS and getattr(transport,'synthetic',False) is True,'TEST_TRANSPORT_REQUIRED')
            else:require(type(transport) is MetaHTTPS,'META_TRANSPORT_REQUIRED');transport.fixed_destination_guard=True
            # After a transmission attempt, collect bounded safe response evidence even if content changes.
            def transport_check():
                if getattr(transport,'trace',{}).get('phase','NOT_STARTED')=='NOT_STARTED':before_send()
            if self.test_mode:status,raw=transport.send(req['body'].encode('utf-8'),secret,transport_check)
            else:
                with network.authorized_meta(scope_sha):status,raw=transport.send(req['body'].encode('utf-8'),secret,transport_check)
            trace=copy.deepcopy(transport.trace)
            require(type(raw) is bytes and len(raw)<=MAX_REPLY,'RESPONSE_SIZE')
            require(bytes(secret) not in raw,'SECRET_ECHO_REJECTED')
            value=strict_json(raw,MAX_REPLY);no_secret_in_decoded(value,secret.decode('ascii'))
            # Visible answers contain a second JSON document. Check decoded strings
            # before retaining even a schema-invalid reply with escaped content.
            if type(value) is dict and type(value.get('output')) is list:
                for item in value['output']:
                    if type(item) is dict and type(item.get('content')) is list:
                        for part in item['content']:
                            if type(part) is dict and part.get('type')=='output_text':
                                answer=strict_json(part['text'].encode('utf-8'),MAX_REPLY)
                                no_secret_in_decoded(answer,secret.decode('ascii'))
            safe_raw=raw;usage=known_usage(value)
            validation='REJECTED'
            review,receipt=parse_response(status,raw,req,draft)
            no_secret_in_decoded(review,secret.decode('ascii'));no_secret_in_decoded(receipt,secret.decode('ascii'))
            validation='SCHEMA_AND_EXACT_QUOTES_VALID'
            receipt.update(provenance='SYNTHETIC_PREFLIGHT_TRANSPORT' if self.test_mode else 'REAL_META_RESPONSE',
                usage_kind='SYNTHETIC_TEST_VALUES' if self.test_mode else 'PROVIDER_REPORTED',
                host_scope=SCHEMA,scope_sha=scope_sha,transport=trace,formal_approval='NOT_ESTABLISHED')
            self.store.outcome(rid,trace,validation,usage,safe_raw,provenance=provenance)
            try:program_current=self.context(req)==context
            except Exception:program_current=False
            # Final evidence must persist before the workspace can expose CURRENT.
            # If its own commit fails, the request stays consumed; no new review
            # becomes current. Registry completion is not workspace acceptance.
            def record_completion():
                self.records.complete(rid,'COMPLETED',{'transport':trace,'content_validation':validation,
                    'usage':usage,'workspace_acceptance':'REQUIRES_WORKSPACE_COMMIT'})
            current=self.store.finish(req,review,receipt,safe_raw,commit_check=record_completion,
                current_allowed=program_current)
            result_written=True
            return {'current':current,'provenance':receipt['provenance']}
        except BaseException as exc:
            reason=code(exc)
            if transport is not None:trace=copy.deepcopy(getattr(transport,'trace',trace))
            if consumed:
                if reason=='SECRET_ECHO_REJECTED':safe_raw=None;usage=None
                try:
                    if result_written:self.store._change(lambda s:self.store._invalidate(s,'CONNECTOR_COMMIT_INCOMPLETE'))
                    self.store.outcome(rid,trace,validation if validation!='NOT_RUN' else 'REJECTED_OR_NOT_AVAILABLE',usage,safe_raw,reason,
                        provenance='SYNTHETIC_PREFLIGHT_TRANSPORT' if self.test_mode else 'REAL_META_ATTEMPT')
                    self.store.fail(rid,reason)
                except Exception:pass
                try:self.records.complete(rid,'REJECTED' if trace['http_status'] is not None else 'UNKNOWN_NO_RETRY',
                    {'transport':trace,'content_validation':validation,'usage':usage,'error':reason})
                except Exception:pass
            raise Refusal(reason) from None
        finally:
            if type(secret) is bytearray:secret[:]=b'\x00'*len(secret)
            self.done.set();self.active.release()
