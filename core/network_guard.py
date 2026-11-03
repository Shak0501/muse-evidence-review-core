"""Process-scoped network fence: local UI plus one explicitly scoped Meta TLS connection."""
import contextvars
from contextlib import contextmanager
import ipaddress
import socket
import sys
from .contracts import Refusal, require

_mode='OFFLINE'
_scope=contextvars.ContextVar('muse_meta_scope',default=None)
BLOCKED=[]

def local(host):
    try:return ipaddress.ip_address(host).is_loopback
    except (ValueError,TypeError):return host=='localhost'

def deny(code):
    BLOCKED.append(code)
    raise Refusal(code)

def audit(event,args):
    if event in ('socket.gethostbyname','socket.gethostbyaddr'):
        deny('NETWORK_RESOLVER_REJECTED')
    if event=='socket.getaddrinfo':
        host,port=args[:2]
        if local(host):return
        if _mode=='LIVE' and _scope.get() is not None and host=='api.meta.ai' and port==443:return
        deny('NETWORK_DESTINATION_REJECTED')
    if event in ('socket.connect','socket.bind','socket.sendto'):
        address=args[-1]
        if not isinstance(address,tuple) or len(address)<2:deny('NETWORK_DESTINATION_REJECTED')
        host,port=address[:2]
        if local(host):return
        scope=_scope.get()
        if event=='socket.connect' and _mode=='LIVE' and scope is not None and (host,port) in scope['addresses']:return
        deny('NETWORK_DESTINATION_REJECTED')

sys.addaudithook(audit)

def configure_live():
    global _mode
    require(_mode!='TEST','TEST_NETWORK_LOCKED')
    _mode='LIVE'

def configure_test():
    global _mode
    require(_mode!='LIVE','TEST_MODE_BEFORE_LIVE_REQUIRED')
    _mode='TEST'

def test_locked():return _mode=='TEST'

@contextmanager
def authorized_meta(scope_sha):
    require(_mode=='LIVE' and type(scope_sha) is str and len(scope_sha)==64,'LIVE_NETWORK_NOT_AUTHORIZED')
    token=_scope.set({'scope_sha':scope_sha,'addresses':set()})
    try:yield
    finally:_scope.reset(token)

def fixed_connection(address,timeout=15,source_address=None):
    require(address==('api.meta.ai',443) and source_address is None,'NETWORK_DESTINATION_REJECTED')
    scope=_scope.get();require(_mode=='LIVE' and scope is not None,'LIVE_NETWORK_NOT_AUTHORIZED')
    answers=socket.getaddrinfo('api.meta.ai',443,type=socket.SOCK_STREAM)
    require(bool(answers),'META_DNS_FAILED')
    family,kind,proto,_,target=answers[0]
    require(ipaddress.ip_address(target[0]).is_global,'NETWORK_DESTINATION_REJECTED')
    scope['addresses']={(target[0],443)}
    sock=socket.socket(family,kind,proto);sock.settimeout(timeout)
    try:sock.connect(target);return sock
    except BaseException:sock.close();raise
