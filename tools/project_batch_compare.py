"""Bounded offline batch comparison of explicitly selected project collections.

Use only this repository's built archive_source_compare binary. Project files
are never executed, changed, or copied to the public repository. All generated
fixtures/reports must remain private. Empty cases and errors are not passes.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess

from project_source_fixture import Project, build

FLOWS = ('printed-speed', 'stored-volume')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def write_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')


def limited_entries(path):
    result = []
    for item in path.iterdir():
        if len(result) >= 10000:
            raise ValueError('Directory inventory exceeds 10000 entries')
        result.append(item)
    return sorted(result)


def discover(roots):
    """One level of project directories per explicitly supplied collection."""
    jobs, seen = [], set()
    for root_arg in roots:
        root = Path(root_arg)
        if root.is_symlink():
            raise ValueError('Collection symlinks unsupported')
        root = root.resolve(strict=True)
        if root in seen:
            raise ValueError('Duplicate collection')
        seen.add(root)
        for child in limited_entries(root):
            if child.is_symlink():
                raise ValueError('Project symlinks unsupported')
            if not child.is_dir() or not (child / 'RESNEW').exists():
                continue
            project = Project(child)
            results = project.path('RESNEW')
            folders = [p.name for p in limited_entries(results)
                       if re.fullmatch(r'\d{4}_\d{1,3}_\d{1,3}', p.name)]
            if not folders:
                jobs.append((root.name + '/' + child.name, child, None))
            else:
                for folder in folders:
                    project.path('RESNEW/' + folder)  # reject links before work
                    jobs.append((root.name + '/' + child.name, child, folder))
            if len(jobs) > 256:
                raise ValueError('Project/folder budget exceeds 256')
    if not jobs:
        raise ValueError('No project directories discovered')
    return jobs


def verify_inputs(project, evidence):
    # Includes the extractor's budgets and path/symlink checks.
    check = Project(project.root)
    return all(check.text(e['member'])[1]['sha256'] == e['sha256'] for e in evidence)


def validate_result(report, fixture, exit_code):
    expected_ids = [c['case_id'] for c in fixture['cases']]
    actual = report.get('cases', [])
    if ([c.get('case_id') for c in actual] != expected_ids
            or report.get('provenance') != fixture['provenance']
            or report.get('skipped') != fixture['skipped']):
        raise ValueError('Comparator report does not match complete input')
    for case in actual:
        metrics = case.get('metrics', {})
        if set(metrics) != {'cm_pdk', 'um_m_s', 'xm_m'}:
            raise ValueError('Comparator metrics incomplete')
        flags = [metric.get('pass') for metric in metrics.values()]
        if any(type(flag) is not bool for flag in flags) or type(case.get('pass')) is not bool:
            raise ValueError('Comparator decisions must be booleans')
        if case['pass'] != all(flags):
            raise ValueError('Comparator decisions inconsistent')
    passed = sum(c['pass'] for c in actual)
    summary = dict(compared=len(actual), passed=passed, failed=len(actual) - passed,
                   skipped=len(fixture['skipped']), all_passed=passed == len(actual))
    if report.get('summary') != summary or exit_code != (0 if summary['all_passed'] else 1):
        raise ValueError('Comparator summary or exit status inconsistent')
    return summary


def run_batch(roots, binary, output):
    binary = Path(binary).resolve(strict=True)
    if not binary.is_file():
        raise ValueError('Comparator must be a built executable file')
    jobs = discover(roots)
    output = Path(output).resolve()
    if any(output.is_relative_to(Path(root).resolve()) for root in roots):
        raise ValueError('Output must be outside original collections')
    output.mkdir(parents=False, exist_ok=False)
    reports = []
    signatures = {flow: {} for flow in FLOWS}
    totals = {flow: Counter(compared=0, passed=0, failed=0) for flow in FLOWS}
    for index, (label, path, folder) in enumerate(jobs):
        if folder is None:
            reports.append(dict(project=label, folder=None, status='no_result_folders'))
            continue
        for flow in FLOWS:
            stem = f'{index:03d}_{flow}'
            row = dict(project=label, folder=folder, flow=flow, artifact_prefix=stem)
            try:
                project = Project(path)
                fixture, notes = build(project, folder, flow)
                write_json(output / (stem + '_cases.json'), fixture)
                write_json(output / (stem + '_notes.json'), notes)
                row['skip_reasons'] = dict(Counter(x['reason'] for x in fixture['skipped']))
                row['selected_files'] = len(notes['evidence'])
                row['source_manifest_sha256'] = fixture['provenance']['selected_files_manifest_sha256']
                if not verify_inputs(project, notes['evidence']):
                    row['selected_inputs_unchanged'] = False
                    raise ValueError('Input file changed after extraction')
                row['selected_inputs_unchanged'] = True
                if not fixture['cases']:
                    row['status'] = 'no_eligible_cases'
                    row['skipped'] = len(fixture['skipped'])
                    row['all_passed'] = False
                else:
                    report_path = output / (stem + '_comparison.json')
                    process = subprocess.run([str(binary), str(output / (stem + '_cases.json')),
                                              str(report_path)],
                                             capture_output=True, timeout=30)
                    if process.returncode not in (0, 1) or not report_path.is_file():
                        raise ValueError('Comparator failed; no successful comparison assigned')
                    if report_path.stat().st_size > 16 * 1024 * 1024:
                        raise ValueError('Comparator report exceeds 16 MiB')
                    report = json.loads(report_path.read_text(encoding='utf-8'))
                    row.update(validate_result(report, fixture, process.returncode))
                    if not verify_inputs(project, notes['evidence']):
                        row['selected_inputs_unchanged'] = False
                        raise ValueError('Input file changed during comparison')
                    row['status'] = 'compared'
                    row['metric_failures'] = dict(Counter(k for c in report['cases']
                        for k, metric in c['metrics'].items() if not metric['pass']))
                    pending = []
                    for case, result in zip(fixture['cases'], report['cases']):
                        # Repeated numeric inputs/expected outputs across variants
                        # are repetitions, not independent validation cases.
                        key = digest({k: case[k] for k in ('coefficient_a', 'air_temperature_c',
                                                          'pdk_mg_m3', 'source', 'expected')})
                        prior = signatures[flow].get(key)
                        if prior is not None and prior['passed'] != result['pass']:
                            raise ValueError('Identical numeric case received different decisions')
                        pending.append((key, result['pass']))
                    for key, passed in pending:
                        signatures[flow].setdefault(key, dict(passed=passed, occurrences=0))
                        signatures[flow][key]['occurrences'] += 1
                    for key in ('compared', 'passed', 'failed'):
                        totals[flow][key] += row[key]
            except (ValueError, OSError, subprocess.TimeoutExpired, UnicodeError) as error:
                row['status'] = 'error'
                row['all_passed'] = False
                for key in ('compared', 'passed', 'failed', 'metric_failures'):
                    row.pop(key, None)
                row['error'] = str(error) if type(error) is ValueError else type(error).__name__
            reports.append(row)
    result = dict(schema_version=1, scope='saved_source_parameters_not_full_project_validation',
        comparator_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        projects=len({path.resolve() for _, path, _ in jobs}), project_folders=len(jobs),
        profiles={}, jobs=reports, limitations=[
            'Empty, skipped and errored cases are not validation passes.',
            'Selected file hashes do not authenticate saved outputs or snapshot freshness.',
            'Numeric duplicates include source IDs/coordinates and expected printed precision.',
            'No original program execution or fixed-wind field validation.'])
    for flow in FLOWS:
        unique = signatures[flow]
        result['profiles'][flow] = {**dict(totals[flow]),
            'unique_numeric_cases': len(unique),
            'unique_passed': sum(item['passed'] for item in unique.values()),
            'repeated_occurrences': sum(item['occurrences'] - 1 for item in unique.values())}
    write_json(output / 'summary.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--roots', type=Path, nargs='+', required=True)
    parser.add_argument('--comparator', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run_batch(args.roots, args.comparator, args.output)
    print(json.dumps(dict(projects=result['projects'], profiles=result['profiles'])))
    return 1 if any(j['status'] != 'compared' or not j['all_passed'] for j in result['jobs']) else 0


if __name__ == '__main__':
    raise SystemExit(main())
