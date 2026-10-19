import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

from verify_checkpoint import verify, manifest_entries, relative_name, main, MAX_FILE


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='era-checkpoint-test-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.data = self.root / 'own-test.txt'
        self.data.write_bytes(b'own synthetic evidence')
        self.manifest = self.root / 'manifest.json'
        self.entry = dict(path=self.data.name, sha256=hashlib.sha256(self.data.read_bytes()).hexdigest())
        self.manifest.write_text(json.dumps(dict(schema_version=1, files=[self.entry])), encoding='utf-8')

    def archive(self, extra=None, replacement=None):
        archive = self.root / 'snapshot.tar.gz'
        with tarfile.open(archive, 'w:gz') as bundle:
            bundle.add(self.manifest, arcname=self.manifest.name)
            if replacement is None:
                bundle.add(self.data, arcname=self.data.name)
            else:
                info = tarfile.TarInfo(self.data.name)
                info.size = len(replacement)
                bundle.addfile(info, io.BytesIO(replacement))
            if extra is not None:
                bundle.addfile(extra, io.BytesIO())
        return archive

    def test_current_files_match_and_missing_or_changed_files_fail(self):
        self.assertTrue(verify(self.manifest, self.root)['verified'])
        self.data.write_bytes(b'changed')
        self.assertEqual(verify(self.manifest, self.root)['checks'][0]['status'], 'mismatch')
        self.data.unlink()
        self.assertFalse(verify(self.manifest, self.root)['verified'])

    def test_archive_verifies_historical_files_without_extracting(self):
        archive = self.archive()
        self.data.write_bytes(b'new working version')
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        result = verify(self.manifest, self.root, archive)
        self.assertTrue(result['verified'])
        self.assertEqual(len(result['checks']), 2)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_archive_corruption_and_manifest_replacement_fail(self):
        self.assertFalse(verify(self.manifest, self.root, self.archive(replacement=b'changed'))['verified'])
        archive = self.archive()
        self.manifest.write_text(json.dumps(dict(schema_version=1, files=[self.entry], extra='changed')))
        self.assertFalse(verify(self.manifest, self.root, archive)['verified'])

    def test_archive_extra_and_duplicate_members_rejected(self):
        for name in ('extra', self.data.name):
            with self.assertRaises(ValueError):
                verify(self.manifest, self.root, self.archive(extra=tarfile.TarInfo(name)))

    def test_archive_traversal_links_and_declared_oversize_rejected(self):
        cases = [tarfile.TarInfo('../escape'), tarfile.TarInfo('link'), tarfile.TarInfo('big')]
        cases[1].type = tarfile.SYMTYPE
        cases[1].linkname = str(self.data)
        # A sparse header with no payload exercises rejection before reading.
        cases[2].size = MAX_FILE + 1
        for info in cases[:2]:
            with self.assertRaises(ValueError):
                verify(self.manifest, self.root, self.archive(extra=info))
        archive = self.root / 'oversized.tar'
        archive.write_bytes(cases[2].tobuf() + bytes(1024))
        with self.assertRaises(ValueError):
            verify(self.manifest, self.root, archive)

    def test_paths_are_portable_and_confined(self):
        for name in ('', '.', '../escape', '/absolute', 'a/../b', 'a//b', './a', 'C:/windows', 'a\\b'):
            with self.assertRaises(ValueError):
                relative_name(name)
        with tempfile.TemporaryDirectory(prefix='era-checkpoint-outside-') as outside:
            target = Path(outside) / 'outside.txt'
            target.write_bytes(b'outside')
            self.data.unlink()
            self.data.symlink_to(target)
            with self.assertRaises(ValueError):
                verify(self.manifest, self.root)

    def test_bad_digest_duplicates_schema_and_self_reference_rejected(self):
        for value in ({}, dict(schema_version=2, files=[self.entry]),
                      dict(schema_version=1, files=[]),
                      dict(schema_version=1, files=[self.entry, self.entry]),
                      dict(schema_version=1, files=[dict(path='a', sha256='invalid')])):
            with self.assertRaises(ValueError):
                manifest_entries(json.dumps(value))
        self.manifest.write_text(json.dumps(dict(schema_version=1, files=[dict(self.entry, path=self.manifest.name)])))
        with self.assertRaises(ValueError):
            verify(self.manifest, self.root)


    def test_cli_exit_codes_distinguish_match_mismatch_and_bad_manifest(self):
        for expected in (0, 1, 2):
            if expected == 1:
                self.data.write_bytes(b'changed')
            elif expected == 2:
                self.manifest.write_text('invalid JSON')
            output = io.StringIO()
            with patch('sys.argv', ['verify_checkpoint', str(self.manifest), '--root', str(self.root)]):
                with redirect_stdout(output):
                    self.assertEqual(main(), expected)
            self.assertEqual(json.loads(output.getvalue())['verified'], expected == 0)


if __name__ == '__main__':
    unittest.main()
