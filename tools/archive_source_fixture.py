"""Read a supplied ERA ZIP archive without extraction or execution.

Build private, narrow point-source parameter comparisons from DAT and RESNEW.
No original archive content belongs in the public repository. Not a complete
ERA importer, launch protocol, or claim that saved exports are fresh/authentic.
"""
import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MEMBER = 1024 * 1024
MAX_READ = 32 * 1024 * 1024
NUMBER = r'-?\d+(?:\.\d+)?'


def decimal(text):
    if not isinstance(text, str) or not re.fullmatch(NUMBER, text) or len(text) > 32:
        raise ValueError('Invalid fixed-decimal number')
    try:
        value = Decimal(text)
    except InvalidOperation as error:
        raise ValueError('Invalid decimal') from error
    if not value.is_finite() or not math.isfinite(float(value)):
        raise ValueError('Nonfinite number')
    return value


def one(pattern, text):
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError('Required report field missing or ambiguous')
    return matches[0]


def block(text, tag):
    lines = [line.strip() for line in text.splitlines()]
    starts = [i for i, line in enumerate(lines) if line == 'beg' + tag]
    ends = [i for i, line in enumerate(lines) if line == 'end' + tag]
    if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
        raise ValueError('Missing, repeated or reversed section markers')
    return [line for line in lines[starts[0] + 1:ends[0]] if line]


class Archive:
    def __init__(self, path):
        path = Path(path)
        if path.stat().st_size > MAX_ARCHIVE:
            raise ValueError('Archive exceeds 128 MiB')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            while data := stream.read(1024 * 1024):
                digest.update(data)
        self.sha256 = digest.hexdigest()
        self.name = path.name
        self.zip = zipfile.ZipFile(path)
        self.members = {}
        self.read_bytes = 0
        try:
            infos = self.zip.infolist()
            if len(infos) > 10000 or sum(i.file_size for i in infos) > 256 * 1024 * 1024:
                raise ValueError('Archive inventory budget exceeded')
            for info in infos:
                name = info.filename.rstrip('/')
                p = PurePosixPath(name)
                if (not name or p.is_absolute() or '..' in p.parts or str(p) != name
                        or '\\' in name or ':' in name or any(ord(c) < 32 for c in name)
                        or stat.S_ISLNK(info.external_attr >> 16)):
                    raise ValueError('Noncanonical or unsafe archive member')
                key = name.casefold()
                if key in self.members:
                    raise ValueError('Case-insensitive duplicate member')
                self.members[key] = info
        except Exception:
            self.zip.close()
            raise

    def close(self):
        self.zip.close()

    def text(self, name):
        info = self.members.get(name.casefold())
        if info is None or info.is_dir():
            raise ValueError('Required archive member missing')
        if info.flag_bits & 1 or info.file_size > MAX_MEMBER:
            raise ValueError('Encrypted or oversized member unsupported')
        if self.read_bytes + info.file_size > MAX_READ:
            raise ValueError('Selected-member read budget exceeded')
        with self.zip.open(info) as stream:
            data = stream.read(MAX_MEMBER + 1)
        if len(data) != info.file_size or len(data) > MAX_MEMBER:
            raise ValueError('Member length inconsistent')
        self.read_bytes += len(data)
        return data.decode('cp1251'), dict(member=info.filename, sha256=hashlib.sha256(data).hexdigest())


def sources(text, pollutant, parse_number=decimal):
    outer = block(text, 'I')
    if not outer or outer[0] != 'beg' + pollutant or outer[-1] != 'end' + pollutant:
        raise ValueError('Only a single pollutant in begI is supported')
    rows = {}
    for line in outer[1:-1]:
        values = line.split()
        if len(values) != 22 or not re.fullmatch(r'\d{14}', values[0]):
            raise ValueError('Unsupported source row layout')
        if not re.fullmatch(r'[1-9]\d*', values[1]):
            raise ValueError('Invalid source regime')
        key = (values[0], int(values[1]))
        if key in rows:
            raise ValueError('Duplicate source/regime')
        for value in values[3:]:
            parse_number(value)
        rows[key] = values
    return rows


def reported_sources(text):
    rows = []
    seen = set()
    for line in text.splitlines():
        if not re.match(r'^\|\s*\d+\s*\|', line):
            continue
        cells = [s.strip() for s in line.strip().strip('|').split('|')]
        if (len(cells) != 8 or not re.fullmatch(r'\d{2}\.\d{2}\.\d{2}\.\d{4}', cells[1])
                or not re.fullmatch(r'[1-9]\d*', cells[2])):
            raise ValueError('Unsupported Cm table layout')
        key = (cells[1].replace('.', ''), int(cells[2]))
        if key in seen:
            raise ValueError('Duplicate reported source/regime')
        seen.add(key)
        for index in (3, 5, 6, 7):
            if decimal(cells[index]) < 0:
                raise ValueError('Negative reported parameter')
        rows.append((key, cells))
    if not rows:
        raise ValueError('No comparable source rows in report')
    return rows


def report_context(city, cm, data, variant, pollutant):
    if 'Модель: Разовые' not in cm or 'МРР-2017' not in cm or 'Модель: Разовые' not in city:
        raise ValueError('Only saved MRR-2017 single-event RESNEW reports supported')
    if 'Здания в объекте не заданы' not in city:
        raise ValueError('Building-free context not established')
    a = decimal(one(r'Коэффициент А\s*=\s*(' + NUMBER + ')', city))
    season, air = one(r'Сезон\s*:\s*(ЛЕТО|ЗИМА)\s*\(температура воздуха\s*(' + NUMBER + ')', cm)
    air = decimal(air)
    city_air = decimal(one(r'Температура ' + ('летняя' if season == 'ЛЕТО' else 'зимняя')
                          + r'\s*=\s*(' + NUMBER + ')', city))
    if air != city_air or a <= 0:
        raise ValueError('Inconsistent climate context')
    pdk = decimal(one(r'ПДКмр для примеси ' + pollutant + r'\s*=\s*(' + NUMBER + ')', cm))
    p_rows = block(data, 'P')
    if len(p_rows) != 1:
        raise ValueError('Only a single pollutant data row supported')
    p = p_rows[0].split()
    if len(p) != 7 or p[0] != pollutant or pdk <= 0 or decimal(p[2]) != pdk:
        raise ValueError('Pollutant/PDK mismatch')
    obj = one(r'Объект\s*:\s*(\d{4})\b', cm)
    year, calc, regime = variant.split('_')
    actual_year = one(r'Расч\.год:\s*(\d{4})\b', cm)
    actual_calc = one(r'Вар\.расч\.\s*:\s*(\d+)\b', cm)
    actual_regime = one(r'Режим раб\.\s*:\s*(\d+)\b', cm)
    if (int(year), int(calc), int(regime)) != (int(actual_year), int(actual_calc), int(actual_regime)):
        raise ValueError('Variant/year/regime mismatch')
    return obj, float(a), float(air), float(pdk)


def make_case(values, expected, context, case_id, evidence):
    _, a, air, pdk = context
    if values[2] != 'P' or expected[4] != 'Т':
        raise ValueError('Unsupported non-point source')
    n = [None, None, None] + [float(decimal(s)) for s in values[3:]]
    if n[4] != 0 or n[15] != 1 or n[5] <= 0 or n[6] <= 0 or n[8] < air:
        raise ValueError('Unsupported height/terrain/flow/temperature conditions')
    emission_resolution = Decimal(10) ** decimal(expected[3]).as_tuple().exponent
    if abs(decimal(values[17]) - decimal(expected[3])) > emission_resolution / 2:
        raise ValueError('Input/report emission mismatch')
    volume = math.pi * n[5] ** 2 * n[6] / 4
    volume_resolution = float(Decimal(10) ** decimal(values[7]).as_tuple().exponent)
    if abs(volume - n[7]) > volume_resolution / 2 + 1e-12 * max(1, abs(volume)):
        raise ValueError('Stored volume inconsistent with circular outlet within print resolution')
    return dict(case_id=case_id, coefficient_a=a, air_temperature_c=air, pdk_mg_m3=pdk,
        source=dict(id=values[0] + ':' + values[1], x_m=n[9], y_m=n[10], height_m=n[3],
            outlet=dict(shape='circular', diameter_m=n[5]), exit_velocity_m_s=n[6],
            gas_temperature_c=n[8], emission_g_s=n[17], settling_factor=n[14]),
        expected=dict(cm_pdk=expected[5], um_m_s=expected[6], xm_m=expected[7]), evidence=evidence)


def build_fixture(archive, variant):
    if not re.fullmatch(r'\d{4}_\d{1,3}_\d{1,3}', variant):
        raise ValueError('Select one explicit year_variant_regime directory')
    cases, skipped = [], []
    pattern = re.compile(r'resnew/' + re.escape(variant) + r'/4_cm(\d{4})\.txt')
    for name in sorted(archive.members):
        match = pattern.fullmatch(name)
        if not match:
            continue
        pollutant = match[1]
        case_id = variant + '/' + pollutant
        if int(pollutant) >= 6000:
            skipped.append(dict(case_id=case_id, reason='Summation groups not supported'))
            continue
        try:
            texts, evidence = [], []
            for path in [name, f'RESNEW/{variant}/2_go{pollutant}.txt',
                         f'DAT/{variant}/dat_{pollutant}.txt', f'DAT/{variant}/ist_{pollutant}.txt']:
                text, entry = archive.text(path)
                texts.append(text)
                evidence.append(entry)
            cm, city, data, source_data = texts
            context = report_context(city, cm, data, variant, pollutant)
            source_rows = sources(source_data, pollutant)
            for (short_code, regime), row in reported_sources(cm):
                row_id = case_id + '/' + short_code + ':' + str(regime)
                try:
                    key = (context[0] + short_code, regime)
                    if key not in source_rows:
                        raise ValueError('Reported source/regime absent from input')
                    cases.append(make_case(source_rows[key], row, context, row_id, evidence))
                except ValueError as error:
                    skipped.append(dict(case_id=row_id, reason=str(error)))
        except (ValueError, UnicodeError, zipfile.BadZipFile) as error:
            # Diagnostics contain our own validation messages, never file contents.
            skipped.append(dict(case_id=case_id, reason=type(error).__name__ + ': '
                                + (str(error) if type(error) is ValueError else 'Unreadable member')))
    return dict(schema_version=1,
        provenance=dict(archive_name=archive.name, archive_sha256=archive.sha256), cases=cases, skipped=skipped)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--variant', required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    archive = Archive(args.archive)
    try:
        result = build_fixture(archive, args.variant)
    finally:
        archive.close()
    with args.report.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps(dict(cases=len(result['cases']), skipped=len(result['skipped']))))
    return 0 if result['cases'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
