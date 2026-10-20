"""Read-only source-parameter diagnostic from an unpacked ERA project.

No project payload belongs in the public repository. Folder names are opaque,
not inferred calculation years. Two explicit flow interpretations are supported;
neither establishes native numeric precision or freshness of saved results.
"""
import argparse
from decimal import Decimal
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re

from archive_source_fixture import NUMBER, block, decimal, one, sources


class Project:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError('Project must be a directory')
        self.evidence = {}
        self.read_bytes = 0

    def path(self, relative):
        p = PurePosixPath(relative)
        if (p.is_absolute() or str(p) != relative or '..' in p.parts
                or '\\' in relative or ':' in relative or not p.parts):
            raise ValueError('Invalid relative project path')
        target = self.root
        for part in p.parts:
            target = target / part
            if target.is_symlink():
                raise ValueError('Project symlinks unsupported')
        if not target.resolve().is_relative_to(self.root):
            raise ValueError('Project path escapes root')
        return target

    def text(self, relative):
        path = self.path(relative)
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError('Missing or oversized project text file')
        with path.open('rb') as stream:
            data = stream.read(1024 * 1024 + 1)
        self.read_bytes += len(data)
        if len(data) > 1024 * 1024 or self.read_bytes > 32 * 1024 * 1024:
            raise ValueError('Project read budget exceeded')
        entry = dict(member=relative, sha256=hashlib.sha256(data).hexdigest())
        if relative in self.evidence and self.evidence[relative] != entry:
            raise ValueError('Project file changed during reading')
        self.evidence[relative] = entry
        return data.decode('cp1251'), entry


def rows(text):
    if 'Коды источников уникальны в рамках всего предприятия' not in text:
        raise ValueError('Short source-code uniqueness not declared')
    result, seen = [], set()
    for line in text.splitlines():
        if not re.match(r'^\|\s*\d+\s*\|', line):
            continue
        cells = [s.strip() for s in line.strip().strip('|').split('|')]
        if (len(cells) != 8 or not re.fullmatch(r'\d{4}', cells[1])
                or not re.fullmatch(r'[1-9]\d*', cells[2])):
            raise ValueError('Unsupported short-code Cm row')
        key = (cells[1], int(cells[2]))
        if key in seen:
            raise ValueError('Ambiguous short source code/regime')
        seen.add(key)
        for i in (3, 5, 6, 7):
            if decimal(cells[i]) < 0:
                raise ValueError('Negative reported parameter')
        result.append((key, cells))
    if not result:
        raise ValueError('No Cm source rows')
    return result


def context(city, cm, data, control, printed_inputs, pollutant):
    if ('Модель: Разовые' not in cm or 'МРР-2017' not in cm
            or 'Модель: Разовые' not in city):
        raise ValueError('Only MRR-2017 single-event reports supported')
    if ('ЗИМА для энергетики и ЛЕТО для остальных' not in cm
            or '+Season               = Max' not in control
            or 'отрицательное значение высоты' not in printed_inputs):
        raise ValueError('Mixed-season height-sign convention not established')
    a = decimal(one(r'Коэффициент А\s*=\s*(' + NUMBER + ')', city))
    summer = decimal(one(r'Температура летняя\s*=\s*(' + NUMBER + ')', city))
    winter = decimal(one(r'Температура зимняя\s*=\s*(' + NUMBER + ')', city))
    pdk = decimal(one(r'ПДКмр для примеси ' + pollutant + r'\s*=\s*(' + NUMBER + ')', cm))
    p_rows = block(data, 'P')
    if len(p_rows) != 1:
        raise ValueError('Ambiguous pollutant data')
    p = p_rows[0].split()
    if len(p) != 7 or p[0] != pollutant or decimal(p[2]) != pdk or pdk <= 0 or a <= 0:
        raise ValueError('PDK/pollutant/climate mismatch')
    obj = one(r'Объект\s*:\s*(\d{4})\b', cm)
    year = one(r'Расч\.год:\s*(\d{4})\b', cm)
    variant = one(r'Вар\.расч\.\s*:\s*(\d+)\b', cm)
    regime = one(r'Режим раб\.\s*:\s*(\d+)\b', cm)
    return obj, float(a), float(summer), float(winter), float(pdk), (year, variant, regime)


def make_case(values, row, ctx, case_id, evidence, flow):
    obj, a, summer, winter, pdk, _ = ctx
    n = [None, None, None] + [float(decimal(s)) for s in values[3:]]
    if not values[0].startswith(obj):
        raise ValueError('Object/source mismatch')
    if values[2] != 'P' or row[4] != 'Т':
        raise ValueError('Unsupported non-point source')
    air = winter if n[3] < 0 else summer
    if n[3] == 0 or n[4] != 0 or n[15] != 1 or n[5] <= 0 or n[6] <= 0 or n[8] < air:
        raise ValueError('Unsupported height/terrain/flow/temperature')
    resolution = Decimal(10) ** decimal(row[3]).as_tuple().exponent
    if abs(decimal(values[17]) - decimal(row[3])) > resolution / 2:
        raise ValueError('Input/report emission mismatch')
    volume_from_printed_speed = math.pi * n[5] ** 2 * n[6] / 4
    velocity_from_volume = 4 * n[7] / (math.pi * n[5] ** 2)
    speed_resolution = float(Decimal(10) ** decimal(values[6]).as_tuple().exponent)
    within_speed_rounding = abs(velocity_from_volume - n[6]) <= speed_resolution / 2
    if flow == 'stored-volume' and (n[7] <= 0 or not within_speed_rounding):
        raise ValueError('Volume-derived speed outside printed-speed rounding interval')
    speed = n[6] if flow == 'printed-speed' else velocity_from_volume
    case = dict(case_id=case_id, coefficient_a=a, air_temperature_c=air, pdk_mg_m3=pdk,
        source=dict(id=values[0] + ':' + values[1], x_m=n[9], y_m=n[10], height_m=abs(n[3]),
            outlet=dict(shape='circular', diameter_m=n[5]), exit_velocity_m_s=speed,
            gas_temperature_c=n[8], emission_g_s=n[17], settling_factor=n[14]),
        expected=dict(cm_pdk=row[5], um_m_s=row[6], xm_m=row[7]), evidence=evidence)
    detail = dict(case_id=case_id, flow_interpretation=flow, stored_volume_m3_s=n[7],
        volume_from_printed_speed_m3_s=volume_from_printed_speed,
        printed_speed_m_s=n[6], speed_from_volume_m_s=velocity_from_volume,
        volume_speed_consistent_with_printed_resolution=within_speed_rounding,
        selected_season='winter' if n[3] < 0 else 'summer')
    return case, detail


def build(project, folder, flow):
    if not re.fullmatch(r'\d{4}_\d{1,3}_\d{1,3}', folder):
        raise ValueError('Select one explicit result/input directory')
    if flow not in ('printed-speed', 'stored-volume'):
        raise ValueError('Invalid flow interpretation')
    directory = project.path('RESNEW/' + folder)
    paths = []
    for i, path in enumerate(directory.iterdir()):
        if i >= 10000:
            raise ValueError('Directory entry budget exceeded')
        if re.fullmatch(r'4_cm\d{4}\.txt', path.name.casefold()):
            paths.append(path)
    if len({p.name.casefold() for p in paths}) != len(paths):
        raise ValueError('Duplicate case-insensitive report name')
    cases, skipped, details, headers = [], [], [], set()
    for path in sorted(paths):
        code = path.stem[-4:]
        base_id = folder + '/' + code
        if int(code) >= 6000:
            skipped.append(dict(case_id=base_id, reason='Summation group unsupported'))
            continue
        try:
            names = [f'RESNEW/{folder}/{path.name}', f'RESNEW/{folder}/2_go{code}.txt',
                f'DAT/{folder}/dat_{code}.txt', f'DAT/{folder}/ist_{code}.txt',
                f'DAT/{folder}/upr_{code}.txt', f'RESNEW/{folder}/3_is{code}.txt']
            read = [project.text(name) for name in names]
            cm, city, data, source, control, printed_inputs = [v[0] for v in read]
            evidence = [v[1] for v in read]
            ctx = context(city, cm, data, control, printed_inputs, code)
            headers.add(ctx[-1])
            mapped = {}
            for (_, regime), values in sources(source, code).items():
                key = (values[0][-4:], regime)
                if key in mapped:
                    raise ValueError('Ambiguous input short source code/regime')
                mapped[key] = values
            for key, row in rows(cm):
                case_id = base_id + '/' + key[0] + ':' + str(key[1])
                try:
                    if key not in mapped:
                        raise ValueError('Reported source missing from input')
                    case, detail = make_case(mapped[key], row, ctx, case_id, evidence, flow)
                    cases.append(case)
                    details.append(detail)
                except ValueError as error:
                    skipped.append(dict(case_id=case_id, reason=str(error)))
        except (ValueError, OSError, UnicodeError) as error:
            skipped.append(dict(case_id=base_id, reason=str(error) if type(error) is ValueError
                                else 'Missing or unreadable project member'))
    if len(headers) > 1:
        raise ValueError('Inconsistent report year/variant/regime across selected directory')
    manifest = sorted(project.evidence.values(), key=lambda e: e['member'])
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    fixture = dict(schema_version=1, provenance=dict(project_name=project.root.name,
        selected_files_manifest_sha256=digest), cases=cases, skipped=skipped)
    notes = dict(schema_version=1, scope='source_parameter_diagnostic_not_complete_project_validation',
        flow_interpretation=flow, report_headers=sorted(headers), evidence=manifest, details=details,
        limitations=['Saved snapshots may be stale and text exports rounded.',
            'No field/optimizer/background/buildings/area-source validation.',
            'Flow profiles are explicit interpretations, not proof of original internal arithmetic.',
            'Manifest hashes only files read, not the entire project.'])
    return fixture, notes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('--folder', required=True)
    parser.add_argument('--flow', choices=['printed-speed', 'stored-volume'], required=True)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--notes', type=Path, required=True)
    args = parser.parse_args()
    project = Project(args.project)
    if any(path.resolve().is_relative_to(project.root) for path in (args.cases, args.notes)):
        raise ValueError('Outputs must remain outside the original project')
    if args.cases.exists() or args.notes.exists() or args.cases.resolve() == args.notes.resolve():
        raise ValueError('Distinct new output files required')
    fixture, notes = build(project, args.folder, args.flow)
    for path, value in [(args.cases, fixture), (args.notes, notes)]:
        with path.open('x', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write('\n')
    print(json.dumps(dict(cases=len(fixture['cases']), skip_records=len(fixture['skipped']))))
    return 0 if fixture['cases'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
