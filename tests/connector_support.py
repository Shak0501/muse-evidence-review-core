"""Synthetic fixtures for the guarded connector tests; never a production credential source."""
import os
import pty
import select
import termios
import threading
import time
from core.contracts import canonical, strict_json, digest, offline_review, MODEL
from core.terminal_credentials import TerminalCredentials

SYNTHETIC_SECRET=b'SYNTHETIC_P2_PTY_ONLY_NOT_A_KEY'
ALL_DECISIONS={k:True for k in ('b1','risk','data_egress','budget_once','final_dispatch')}

def wire(req,draft):
    return {'id':'resp_synthetic_p2','model':MODEL,'status':'completed','tools':[],
        'background':False,'store':False,'service_tier':'default',
        'usage':{'input_tokens':100,'output_tokens':400,'total_tokens':500},
        'output':[{'type':'message','role':'assistant','status':'completed','content':[
            {'type':'output_text','text':canonical(offline_review(req,draft)).decode(),'annotations':[]}]}]}

class ControlledTransport:
    synthetic=True
    def __init__(self,store,mutation=None,status=200,effect=None,failure=None):
        self.store=store;self.mutation=mutation;self.status=status;self.effect=effect;self.failure=failure
        self.calls=0;self.trace={'phase':'NOT_STARTED','http_status':None};self.secret_ref=None
    def send(self,body,secret,still_current):
        still_current();self.calls+=1;self.secret_ref=secret
        self.trace={'phase':'ATTEMPTED_UNKNOWN','http_status':None}
        assert bytes(secret)==SYNTHETIC_SECRET
        b=strict_json(body);envelope=strict_json(b['input'][0]['content'].encode())
        req=self.store.request(envelope['request_id'])
        assert digest(body)==req['body_sha']
        draft=envelope['saved_draft']['text']
        if self.effect:self.effect()
        if self.failure:raise self.failure
        reply=wire(req,draft)
        if self.mutation:self.mutation(reply)
        self.trace={'phase':'RESPONSE_BODY_RECEIVED','http_status':self.status}
        return self.status,canonical(reply)

class PTYPump:
    def __init__(self,timeout=2):
        self.master,self.slave=pty.openpty();self.original=termios.tcgetattr(self.slave)
        self.credentials=TerminalCredentials(timeout,lambda:os.dup(self.slave));self.output=bytearray();self.worker=None
        self.ready=threading.Event();self.error=None
    def arm(self,data=SYNTHETIC_SECRET+b'\n',signal=None):
        self.output=bytearray();self.ready.clear();self.error=None
        def feed():
            deadline=time.monotonic()+4
            try:
                while time.monotonic()<deadline:
                    r,_,_=select.select([self.master],[],[],.05)
                    if r:
                        self.output.extend(os.read(self.master,8192))
                        if b'bounded timeout): ' in self.output:
                            self.ready.set()
                            if signal:signal()
                            if data is not None:os.write(self.master,data)
                            return
                self.error='PROMPT_NOT_OBSERVED'
            except OSError:self.error='PTY_CLOSED'
        self.worker=threading.Thread(target=feed,daemon=True);self.worker.start()
    def finish(self):
        if self.worker:self.worker.join(5)
        while select.select([self.master],[],[],.02)[0]:self.output.extend(os.read(self.master,8192))
        assert self.error is None,self.error
        assert termios.tcgetattr(self.slave)==self.original,'TERMINAL_NOT_RESTORED'
        assert SYNTHETIC_SECRET not in self.output,'SECRET_ECHO'
    def close(self):
        os.close(self.master);os.close(self.slave)
