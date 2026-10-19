"""Read-only hash verification of local evidence or a checkpoint tar archive.

Never extracts an archive, executes its contents, or changes a manifest.
Hashes prove agreement with a chosen manifest, not authorship or correctness.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

MAX_MEMBERS = 1024
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024


def relative_name(value):
    if (not isinstance(value, str) or not value or '\\' in value or ':' in value
            or any(ord(character) < 32 for character in value)):
        raise ValueError('Expected a portable relative evidence path')
    path = PurePosixPath(value)
    if not path.parts or path.is_absolute() or '..' in path.parts or str(path) != value:
        raise ValueError('Noncanonical or escaping evidence path: ' + value)
    return value


def confined(root, name):
    path = (root / relative_name(name)).resolve()
    if not path.is_relative_to(root):
        raise ValueError('Evidence symlink escapes the selected root: ' + name)
    return path


def digest_stream(stream):
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(1024 * 1024):
        size += len(chunk)
        if size > MAX_FILE:
            raise ValueError('Evidence file exceeds the 128 MiB verification limit')
        digest.update(chunk)
    return digest.hexdigest()


def manifest_entries(raw):
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or manifest.get('schema_version') != 1:
        raise ValueError('Unsupported checkpoint schema')
    files = manifest.get('files')
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_MEMBERS - 1:
        raise ValueError('Invalid checkpoint file count')
    expected = {}
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError('Invalid checkpoint entry')
        name = relative_name(entry.get('path'))
        digest = entry.get('sha256')
        if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None:
            raise ValueError('Invalid SHA-256 for ' + name)
        if name in expected:
            raise ValueError('Duplicate checkpoint path: ' + name)
        expected[name] = digest
    return expected


def verify(manifest_path, root, archive=None):
    root = Path(root).resolve()
    manifest_path = Path(manifest_path).resolve()
    if not manifest_path.is_relative_to(root):
        raise ValueError('Manifest must be inside the selected workspace root')
    manifest_name = relative_name(manifest_path.relative_to(root).as_posix())
    if manifest_path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('Manifest exceeds 4 MiB')
    raw = manifest_path.read_bytes()
    expected = manifest_entries(raw)
    if manifest_name in expected:
        raise ValueError('Self-referential checkpoint manifest')
    checks = []
    if archive is not None:
        expected[manifest_name] = hashlib.sha256(raw).hexdigest()
        with tarfile.open(archive, mode='r:*') as bundle:
            members = {}
            total = 0
            for member in bundle:
                name = relative_name(member.name)
                total += member.size
                if (name in members or not member.isfile() or not 0 <= member.size <= MAX_FILE
                        or total > MAX_TOTAL or len(members) >= MAX_MEMBERS):
                    raise ValueError('Unsafe, duplicate or oversized archive member: ' + name)
                members[name] = member
            if set(members) != set(expected):
                raise ValueError('Archive member set differs from the manifest plus manifest file')
            for name, digest in expected.items():
                with bundle.extractfile(members[name]) as stream:
                    actual = digest_stream(stream)
                checks.append(dict(path=name, status='ok' if actual == digest else 'mismatch',
                                   expected_sha256=digest, actual_sha256=actual))
    else:
        total = 0
        for name, digest in expected.items():
            path = confined(root, name)
            if not path.is_file():
                checks.append(dict(path=name, status='missing_or_not_regular_file'))
                continue
            total += path.stat().st_size
            if total > MAX_TOTAL:
                raise ValueError('Evidence set exceeds 512 MiB')
            with path.open('rb') as stream:
                actual = digest_stream(stream)
            checks.append(dict(path=name, status='ok' if actual == digest else 'mismatch',
                               expected_sha256=digest, actual_sha256=actual))
    return dict(verified=all(item['status'] == 'ok' for item in checks),
                mode='archive_without_extraction' if archive else 'current_files', checks=checks,
                meaning='Agreement with selected manifest only; not authenticity or numerical validation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.manifest, args.root, args.archive)
    except (ValueError, OSError, tarfile.TarError) as error:
        print(json.dumps(dict(verified=False, error=str(error)), ensure_ascii=False))
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result['verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
