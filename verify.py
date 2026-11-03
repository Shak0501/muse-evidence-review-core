"""Verify this new core's package, not any private historical candidate."""
import hashlib
import json
from pathlib import Path


def verify(root):
    root = Path(root)
    manifest = json.loads((root/'MANIFEST.json').read_text('utf-8'))
    assert manifest['schema'] == 'MUSE_PUBLIC_CORE_MANIFEST_1'
    expected = manifest['files']
    actual = set()
    for path in root.rglob('*'):
        rel = path.relative_to(root)
        if rel.parts[0] in ('.git', '.muse-local'):
            continue
        assert not path.is_symlink(), 'SYMLINK_REJECTED'
        if path.is_file() and str(rel) != 'MANIFEST.json':
            actual.add(rel.as_posix())
    assert actual == set(expected), 'UNLISTED_OR_MISSING_FILE'
    for name, entry in expected.items():
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        raw = (root/name).read_bytes()
        assert len(raw) == entry['bytes'] and hashlib.sha256(raw).hexdigest() == entry['sha256'], 'FILE_IDENTITY'
    return {'manifest': 'PASS', 'files': len(expected)}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent)))
