"""Synthetic archives only; no ERA material is required for these tests."""
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from archive_source_fixture import Archive, block, build_fixture, decimal, sources


VARIANT = '2026_1_1'
SOURCE = '12340102030004 1 P 10.0 0.0 1.000 4.00 3.1415927 50.0 2.0 3.0 0.0 0.0 0.0 1.0 1.00 0 0.0100000 0 0 0 0'
CM = '''ПК ЭРА v4.0. Модель: Разовые
МРР-2017
Объект :1234 Test
Вар.расч. :1 Расч.год: 2026
Режим раб.:01
Сезон :ЛЕТО (температура воздуха 20.0 град.С)
ПДКмр для примеси 0301 = 0.5 мг/м3
| 1 |01.02.03.0004| 1 |0.010000| Т |0.123456|1.20|20.1|
'''
CITY = '''Модель: Разовые
Коэффициент А = 180
Температура летняя = 20.0
Здания в объекте не заданы
'''


def members():
    return {
        f'RESNEW/{VARIANT}/4_Cm0301.txt': CM,
        f'RESNEW/{VARIANT}/2_go0301.txt': CITY,
        f'DAT/{VARIANT}/dat_0301.txt': 'begP\n0301 -1.0 0.5000000 0 0 0 0\nendP\n',
        f'DAT/{VARIANT}/ist_0301.txt': 'begI\nbeg0301\n' + SOURCE
            + '\nend0301\nendI\nbeg2\nbeg0301\nNOT THE SELECTED SECTION\nend0301\nend2\n',
    }


class ArchiveFixtureTests(unittest.TestCase):
    def extract(self, content, action=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic.era'
            with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as out:
                for name, text in content.items():
                    out.writestr(name, text.encode('cp1251'))
            archive = Archive(path)
            try:
                return action(archive) if action else build_fixture(archive, VARIANT)
            finally:
                archive.close()

    def test_complete_pair_and_evidence_without_extracting_files(self):
        result = self.extract(members())
        self.assertEqual(len(result['cases']), 1)
        self.assertEqual(result['skipped'], [])
        case = result['cases'][0]
        self.assertEqual(case['source']['id'], '12340102030004:1')
        self.assertEqual(case['source']['outlet']['diameter_m'], 1.0)
        self.assertEqual(case['expected']['cm_pdk'], '0.123456')
        self.assertEqual(case['pdk_mg_m3'], 0.5)
        self.assertEqual(len(case['evidence']), 4)
        self.assertTrue(all(len(item['sha256']) == 64 for item in case['evidence']))

    def test_archive_names_are_case_insensitive_but_unambiguous(self):
        self.assertEqual(len(self.extract({k.upper(): v for k, v in members().items()})['cases']), 1)
        data = members()
        data[f'resnew/{VARIANT}/4_cm0301.txt'] = CM
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.extract(data)

    def test_unsafe_paths_and_symlinks_rejected_before_member_reads(self):
        for name in ('../outside', '/absolute', 'a\\b', 'C:drive', 'a/./b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.extract({name: 'x'})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'symlink.zip'
            with zipfile.ZipFile(path, 'w') as out:
                info = zipfile.ZipInfo('link')
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                out.writestr(info, 'destination')
            with self.assertRaises(ValueError):
                Archive(path)

    def test_member_budgets_encryption_and_missing_member(self):
        with patch('archive_source_fixture.MAX_MEMBER', 16):
            result = self.extract(members())
            self.assertEqual(result['cases'], [])
            self.assertIn('oversized', result['skipped'][0]['reason'])
        with patch('archive_source_fixture.MAX_READ', 16):
            self.assertEqual(self.extract(members())['cases'], [])
        def encrypted(archive):
            archive.members[f'resnew/{VARIANT}/4_cm0301.txt'].flag_bits |= 1
            return build_fixture(archive, VARIANT)
        self.assertEqual(self.extract(members(), encrypted)['cases'], [])
        data = members()
        del data[f'DAT/{VARIANT}/dat_0301.txt']
        self.assertEqual(self.extract(data)['cases'], [])

    def test_context_mismatches_do_not_become_cases(self):
        for old, new in [('Расч.год: 2026', 'Расч.год: 2025'),
                         ('Модель: Разовые', 'Модель: Годовые'),
                         ('0.5 мг/м3', '0.4 мг/м3'),
                         ('воздуха 20.0', 'воздуха 21.0')]:
            data = members()
            data[f'RESNEW/{VARIANT}/4_Cm0301.txt'] = CM.replace(old, new)
            with self.subTest(old=old):
                self.assertEqual(self.extract(data)['cases'], [])

    def test_unsupported_source_emission_and_volume_are_explicit_skips(self):
        for old, new in [('1 P ', '1 A1 '), ('1.00 0', '1.10 0'),
                         ('3.1415927', '4.0000000'), ('0.0100000', '0.0200000')]:
            data = members()
            key = f'DAT/{VARIANT}/ist_0301.txt'
            data[key] = data[key].replace(old, new)
            with self.subTest(old=old):
                result = self.extract(data)
                self.assertEqual(result['cases'], [])
                self.assertEqual(len(result['skipped']), 1)

    def test_duplicate_and_malformed_sources_fail_closed(self):
        for content in ('begI\nbeg0301\n' + SOURCE + '\n' + SOURCE + '\nend0301\nendI',
                        'begI\nbeg0301\nwrong row\nend0301\nendI',
                        'begI\nbeg0302\n' + SOURCE + '\nend0302\nendI'):
            with self.assertRaises(ValueError):
                sources(content, '0301')
        for content in ('endI\nbegI', 'begI\nbegI\nendI', 'begI'):
            with self.assertRaises(ValueError):
                block(content, 'I')

    def test_fixed_decimal_and_explicit_variant_validation(self):
        for text in ('NaN', '1e3', 'Infinity', '1,2', ' 1', '9' * 33):
            with self.assertRaises(ValueError):
                decimal(text)
        def invalid_variant(archive):
            with self.assertRaises(ValueError):
                build_fixture(archive, '../2026_1_1')
        self.extract(members(), invalid_variant)

    def test_summation_group_is_not_silently_treated_as_one_pollutant(self):
        data = members()
        data[f'RESNEW/{VARIANT}/4_Cm6200.txt'] = 'not a supported single pollutant'
        result = self.extract(data)
        self.assertEqual(len(result['cases']), 1)
        self.assertIn('Summation', result['skipped'][0]['reason'])


if __name__ == '__main__':
    unittest.main()
