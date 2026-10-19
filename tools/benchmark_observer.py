"""Reproducible synthetic observer benchmark; no vendor input is required.

Compares complete trace semantics, excluding observer provenance and timing.
Timing is descriptive, never a CI pass/fail threshold or a prediction for ERA.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import tempfile
import time

from loader_trace import trace
from native_observer import build_library
from test_loader_trace import synthetic_pe


def benchmark(instructions=1_000_000, repeats=3):
    if type(instructions) is not int or not 1 <= instructions <= 20_000_000:
        raise ValueError('Benchmark instruction limit must be 1..20000000')
    if type(repeats) is not int or not 1 <= repeats <= 10:
        raise ValueError('Benchmark repeats must be 1..10')
    started = time.monotonic()
    _, _, metadata = build_library()
    setup_seconds = time.monotonic() - started
    result = dict(schema_version=1, workload='Own synthetic x86 PE loops, not ERA',
                  instructions=instructions, repeats=repeats, observer=metadata,
                  native_setup_seconds=setup_seconds, cases={})
    with tempfile.TemporaryDirectory(prefix='era-observer-benchmark-') as directory:
        for name, code in [('arithmetic', bytes.fromhex('40 31c2 ebfb')),
                           ('stack_writes', bytes.fromhex('ff0424 ebfb'))]:
            path = Path(directory) / (name + '.exe')
            path.write_bytes(synthetic_pe(code))
            samples = {'python': [], 'rust': []}
            expected = None
            for repeat in range(repeats):
                # Alternate order to reduce systematic first-run bias.
                for observer in (('python', 'rust') if repeat % 2 == 0 else ('rust', 'python')):
                    report = trace(path, None, 0, instructions, 120., observer=observer)
                    if report['reason'] != 'instruction_limit' or report['instructions'] != instructions:
                        raise RuntimeError('Benchmark did not finish the requested instruction budget')
                    semantics = {k: v for k, v in report.items()
                                 if k not in ('instruction_observer', 'elapsed_seconds')}
                    if expected is None:
                        expected = semantics
                    elif expected != semantics:
                        raise RuntimeError(f'{name}: observer results differ')
                    samples[observer].append(report['elapsed_seconds'])
            medians = {mode: statistics.median(values) for mode, values in samples.items()}
            result['cases'][name] = dict(seconds=samples, median_seconds=medians,
                speedup=medians['python'] / medians['rust'] if medians['rust'] else None,
                semantic_reports_equal=True,
                semantic_report_sha256=hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest())
    result['source_hashes'] = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in ('benchmark_observer.py', 'test_loader_trace.py', 'loader_trace.py',
                     'native_observer.py', 'trace_observer.rs')}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--instructions', type=int, default=1_000_000)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    if args.report.exists():
        parser.error('Report already exists; choose a new evidence filename')
    result = benchmark(args.instructions, args.repeats)
    with args.report.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
