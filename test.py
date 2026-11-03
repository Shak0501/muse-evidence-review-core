"""Run targeted tests with process-scoped external socket attempts denied."""
import ipaddress
import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
counts={'external_socket_denied':0,'loopback_connects':0,'child_denied':0}
def audit(event,args):
    if event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn'):
        counts['child_denied']+=1;raise PermissionError('TEST_CHILD_DENIED')
    if event=='socket.connect':
        address=args[1]
        try:local=ipaddress.ip_address(address[0]).is_loopback
        except (ValueError,TypeError,IndexError):local=False
        if not local:
            counts['external_socket_denied']+=1;raise PermissionError('TEST_EXTERNAL_NETWORK_DENIED')
        counts['loopback_connects']+=1
sys.addaudithook(audit)
suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
result=unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps({'methods':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
    'synthetic_only':True,'real_meta_requests':0,'scope':'THIS_PYTHON_TEST_PROCESS_NOT_HOST_WIDE','audit':counts}))
raise SystemExit(not result.wasSuccessful())
