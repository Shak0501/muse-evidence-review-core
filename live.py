"""Independent demo Live entry: startup never obtains credentials or dispatches a request."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from app import main
from core.meta_live import safe_code
import json

if __name__=='__main__':
    try:main(live=True)
    except Exception as exc:
        print(json.dumps({'error':safe_code(exc),'automatic_retry':False}),flush=True)
        raise SystemExit(1)
