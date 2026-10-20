"""Synthetic project files only; no user data."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from project_source_fixture import Project, build, rows
from test_archive_source_fixture import members, VARIANT


def project_members():
    data = members()
    cm = f'RESNEW/{VARIANT}/4_Cm0301.txt'
    data[cm] = data[cm].replace('01.02.03.0004', '0004').replace(
        'Сезон :ЛЕТО (температура воздуха 20.0 град.С)',
        'Сезон :ЗИМА для энергетики и ЛЕТО для остальных')
    data[cm] += '\nКоды источников уникальны в рамках всего предприятия\n'
    data[f'RESNEW/{VARIANT}/2_go0301.txt'] += 'Температура зимняя = -20.0\n'
    data[f'RESNEW/{VARIANT}/3_is0301.txt'] = 'Признак для зимы - отрицательное значение высоты\n'
    data[f'DAT/{VARIANT}/upr_0301.txt'] = 'begC\n+Season               = Max\nendC\n'
    return data


class ProjectFixtureTests(unittest.TestCase):
    def run_build(self, data=None, flow='printed-speed'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in (project_members() if data is None else data).items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(text.encode('cp1251'))
            before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
            result = build(Project(root), VARIANT, flow)
            self.assertEqual(before, {p: p.read_bytes() for p in root.rglob('*') if p.is_file()})
            return result

    def test_pair_manifest_and_both_flow_interpretations(self):
        raw, raw_notes = self.run_build()
        volume, notes = self.run_build(flow='stored-volume')
        self.assertEqual(len(raw['cases']), 1)
        self.assertEqual(raw['skipped'], [])
        self.assertEqual(raw['provenance']['selected_files_manifest_sha256'],
                         volume['provenance']['selected_files_manifest_sha256'])
        self.assertEqual(len(notes['evidence']), 6)
        self.assertEqual(raw_notes['details'][0]['flow_interpretation'], 'printed-speed')
        self.assertEqual(notes['details'][0]['flow_interpretation'], 'stored-volume')
        self.assertEqual(raw['cases'][0]['source']['exit_velocity_m_s'], 4.)
        self.assertNotEqual(volume['cases'][0]['source']['exit_velocity_m_s'], 4.)

    def test_negative_height_selects_winter_not_background_flag(self):
        data = project_members()
        key = f'DAT/{VARIANT}/ist_0301.txt'
        data[key] = data[key].replace('P 10.0', 'P -10.0')
        fixture, notes = self.run_build(data)
        self.assertEqual(fixture['cases'][0]['air_temperature_c'], -20.)
        self.assertEqual(fixture['cases'][0]['source']['height_m'], 10.)
        self.assertEqual(notes['details'][0]['selected_season'], 'winter')

    def test_flow_inconsistency_not_silently_fixed(self):
        data = project_members()
        key = f'DAT/{VARIANT}/ist_0301.txt'
        data[key] = data[key].replace('3.1415927', '4.0000000')
        raw, notes = self.run_build(data)
        self.assertEqual(len(raw['cases']), 1)
        self.assertFalse(notes['details'][0]['volume_speed_consistent_with_printed_resolution'])
        derived, _ = self.run_build(data, 'stored-volume')
        self.assertEqual(derived['cases'], [])
        self.assertIn('rounding interval', derived['skipped'][0]['reason'])

    def test_unsupported_and_mismatched_inputs_are_skips(self):
        key = f'DAT/{VARIANT}/ist_0301.txt'
        for old, new in [('1 P ', '1 A1 '), ('12340102030004', '99990102030004'),
                         ('0.0100000', '0.0200000'), ('1.00 0', '1.10 0')]:
            data = project_members()
            data[key] = data[key].replace(old, new)
            fixture, _ = self.run_build(data)
            self.assertEqual(fixture['cases'], [])
            self.assertEqual(len(fixture['skipped']), 1)

    def test_unknown_season_and_short_code_ambiguity_rejected(self):
        data = project_members()
        data[f'DAT/{VARIANT}/upr_0301.txt'] = '+Season = Winter'
        self.assertEqual(self.run_build(data)[0]['cases'], [])
        cm = project_members()[f'RESNEW/{VARIANT}/4_Cm0301.txt']
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            rows(cm + '| 2 |0004|1|0.01|Т|0.1|1.0|20.1|\n')
        with self.assertRaisesRegex(ValueError, 'uniqueness'):
            rows(cm.replace('Коды источников уникальны в рамках всего предприятия', ''))

    def test_kernel_speed_limit_is_an_explicit_skip_not_batch_failure(self):
        data = project_members()
        key = f'DAT/{VARIANT}/ist_0301.txt'
        data[key] = data[key].replace('4.00 3.1415927', '400.00 314.1592654')
        for flow in ['printed-speed', 'stored-volume']:
            fixture, _ = self.run_build(data, flow)
            self.assertEqual(fixture['cases'], [])
            self.assertIn('330 m/s', fixture['skipped'][0]['reason'])
        data[key] = data[key].replace('400.00 314.1592654', '330.00 259.1813939')
        self.assertEqual(len(self.run_build(data)[0]['cases']), 1)

    def test_negative_delta_temperature_is_not_replaced_with_zero(self):
        data = project_members()
        key = f'DAT/{VARIANT}/ist_0301.txt'
        data[key] = data[key].replace('50.0 2.0', '19.0 2.0')
        fixture, _ = self.run_build(data)
        self.assertEqual(fixture['cases'], [])
        self.assertEqual(fixture['skipped'][0]['reason'],
                         'Gas temperature below ambient unsupported')

    def test_path_and_selection_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Project(directory)
            for value in ['../outside', '/absolute', 'a\\b', 'a/./b', 'C:x']:
                with self.assertRaises(ValueError):
                    project.path(value)
            with self.assertRaises(ValueError):
                build(project, '../2026_1_1', 'printed-speed')
            with self.assertRaises(ValueError):
                build(project, VARIANT, 'guess')
            link = Path(directory) / 'link'
            try:
                link.symlink_to(Path(directory))
            except OSError:
                pass  # Windows runners may not grant symlink privileges.
            else:
                with self.assertRaisesRegex(ValueError, 'symlinks'):
                    project.path('link/file')

    def test_cli_exclusive_output_and_no_original_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'project'
            for name, value in project_members().items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value.encode('cp1251'))
            cases, notes = Path(directory) / 'cases.json', Path(directory) / 'notes.json'
            args = [sys.executable, str(Path(__file__).with_name('project_source_fixture.py')),
                str(root), '--folder', VARIANT, '--flow', 'printed-speed',
                '--cases', str(cases), '--notes', str(notes)]
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            before = cases.read_bytes()
            self.assertEqual(len(json.loads(before)['cases']), 1)
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            self.assertEqual(before, cases.read_bytes())
            args[args.index('--cases') + 1] = str(root / 'forbidden-output.json')
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            self.assertFalse((root / 'forbidden-output.json').exists())


if __name__ == '__main__':
    unittest.main()
