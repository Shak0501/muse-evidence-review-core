"""P2 bounded verification: synthetic secrets, PTYs, controlled transport, loopback only."""
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from core import network_guard
network_guard.configure_test()
from verify import verify
verify(ROOT)
suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='connector_checks.py')
result=unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps({'methods':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
    'real_meta_requests':0,'synthetic_credentials_only':True,'network_scope':'GUARDED_TEST_PROCESS_AND_EXPLICIT_CHILDREN_NOT_HOST_WIDE',
    'blocked_network_attempts':network_guard.BLOCKED}))
raise SystemExit(not result.wasSuccessful())
