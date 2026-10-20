"""Synthetic collections and a mocked own comparator; no original software."""
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from project_batch_compare import discover, run_batch, validate_result, write_json
from test_project_source_fixture import project_members


def setup_collection(base, copies=1, content=None):
    root = base / 'collection'
    for i in range(copies):
        project = root / f'project{i}'
        for name, value in (project_members() if content is None else content).items():
            path = project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value.encode('cp1251'))
    binary = base / 'own-comparator-placeholder'
    binary.write_text('Not executable; subprocess is mocked.', encoding='utf-8')
    return root, binary


def synthetic_report(fixture, passed=True):
    cases = [dict(case_id=c['case_id'], pass_=passed, metrics={
        k: {'pass': passed} for k in ('cm_pdk', 'um_m_s', 'xm_m')}) for c in fixture['cases']]
    for case in cases:
        case['pass'] = case.pop('pass_')
    return dict(provenance=fixture['provenance'], skipped=fixture['skipped'], cases=cases,
        summary=dict(compared=len(cases), passed=len(cases) if passed else 0,
                     failed=0 if passed else len(cases), skipped=len(fixture['skipped']),
                     all_passed=passed))


def fake_comparator(args, **kwargs):
    fixture = json.loads(Path(args[1]).read_text(encoding='utf-8'))
    write_json(Path(args[2]), synthetic_report(fixture))
    return SimpleNamespace(returncode=0)


class ProjectBatchTests(unittest.TestCase):
    def test_repeated_variants_not_counted_as_independent_cases(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root, binary = setup_collection(base, copies=2)
            with patch('project_batch_compare.subprocess.run', side_effect=fake_comparator):
                result = run_batch([root], binary, base / 'output')
            self.assertEqual(result['projects'], 2)
            for flow in result['profiles'].values():
                self.assertEqual(flow['compared'], 2)
                self.assertEqual(flow['passed'], 2)
                self.assertEqual(flow['unique_numeric_cases'], 1)
                self.assertEqual(flow['repeated_occurrences'], 1)
            self.assertTrue(all(j['selected_inputs_unchanged'] for j in result['jobs']))

    def test_no_eligible_cases_do_not_run_comparator_or_pass(self):
        data = project_members()
        key = next(k for k in data if '/ist_' in k)
        data[key] = data[key].replace('50.0 2.0', '19.0 2.0')
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root, binary = setup_collection(base, content=data)
            with patch('project_batch_compare.subprocess.run') as run:
                result = run_batch([root], binary, base / 'output')
            run.assert_not_called()
            self.assertTrue(all(j['status'] == 'no_eligible_cases' for j in result['jobs']))
            self.assertTrue(all(not j['all_passed'] for j in result['jobs']))

    def test_missing_results_are_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root, binary = setup_collection(base)
            (root / 'empty' / 'RESNEW').mkdir(parents=True)
            with patch('project_batch_compare.subprocess.run', side_effect=fake_comparator):
                result = run_batch([root], binary, base / 'output')
            self.assertEqual(result['jobs'][0]['status'], 'no_result_folders')

    def test_bad_comparator_cannot_produce_a_pass(self):
        def incomplete(args, **kwargs):
            fixture = json.loads(Path(args[1]).read_text(encoding='utf-8'))
            report = synthetic_report(fixture)
            report['cases'] = []
            write_json(Path(args[2]), report)
            return SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root, binary = setup_collection(base)
            for index, side_effect in enumerate([incomplete, lambda *a, **k: SimpleNamespace(returncode=2)]):
                with patch('project_batch_compare.subprocess.run', side_effect=side_effect):
                    result = run_batch([root], binary, base / f'output{index}')
                self.assertTrue(all(j['status'] == 'error' for j in result['jobs']))
                self.assertEqual(result['profiles']['printed-speed']['unique_numeric_cases'], 0)

    def test_mismatch_is_preserved(self):
        def mismatch(args, **kwargs):
            fixture = json.loads(Path(args[1]).read_text(encoding='utf-8'))
            write_json(Path(args[2]), synthetic_report(fixture, False))
            return SimpleNamespace(returncode=1)
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root, binary = setup_collection(base)
            with patch('project_batch_compare.subprocess.run', side_effect=mismatch):
                result = run_batch([root], binary, base / 'output')
            self.assertEqual(result['profiles']['printed-speed']['failed'], 1)

    def test_paths_selection_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root, binary = setup_collection(base)
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                discover([root, root])
            with self.assertRaisesRegex(ValueError, 'outside'):
                run_batch([root], binary, root / 'output')
            (base / 'existing').mkdir()
            with self.assertRaises(FileExistsError):
                run_batch([root], binary, base / 'existing')

    def test_report_contract_checks_decisions_and_exit_status(self):
        fixture = dict(provenance={'synthetic': True}, skipped=[], cases=[{'case_id': 'one'}])
        report = synthetic_report(fixture)
        with self.assertRaises(ValueError):
            validate_result(report, fixture, 1)
        report['cases'][0]['metrics']['cm_pdk']['pass'] = 1
        with self.assertRaises(ValueError):
            validate_result(report, fixture, 0)
        report = synthetic_report(fixture)
        report['summary']['compared'] = 0
        with self.assertRaises(ValueError):
            validate_result(report, fixture, 0)

    def test_changed_input_invalidates_comparison(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root, binary = setup_collection(base)
            # Each flow succeeds on first rehash, fails on second.
            with patch('project_batch_compare.subprocess.run', side_effect=fake_comparator), \
                    patch('project_batch_compare.verify_inputs', side_effect=[True, False, True, False]):
                result = run_batch([root], binary, base / 'output')
            self.assertTrue(all(j['status'] == 'error' for j in result['jobs']))
            self.assertTrue(all('passed' not in j for j in result['jobs']))
            self.assertTrue(all(not j['selected_inputs_unchanged'] for j in result['jobs']))
            self.assertEqual(result['profiles']['printed-speed']['unique_numeric_cases'], 0)


if __name__ == '__main__':
    unittest.main()
