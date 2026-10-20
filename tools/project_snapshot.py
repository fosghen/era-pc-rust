"""Report-side source snapshot checks; not proof of full project freshness."""
from decimal import Decimal, localcontext
import re

HEADERS = ('Код', 'Реж', 'Тип', 'H1', 'H2', 'D', 'Wo', 'V1', 'T',
           'X1', 'Y1', 'X2', 'Y2', 'Width', 'F', 'КР', 'Ди', 'Выброс', 'RoГВС')
PARAMETERS = (3, 4, 5, 6, 7, 8, 14, 15, 17)


def source_table(text):
    headers = [line for line in text.splitlines()
               if tuple(cell.strip() for cell in line.split('|')) == HEADERS]
    if len(headers) != 1:
        raise ValueError('Missing or ambiguous report-side source table header')
    header = headers[0]
    boundaries = [-1] + [i for i, char in enumerate(header) if char == '|']
    result = {}
    for line in text.splitlines():
        if not re.match(r'^\s*\d{4}\s+\d+\s+', line):
            continue
        ends = boundaries + [max(len(header), len(line))]
        cells = [line[a + 1:b].strip() for a, b in zip(ends, ends[1:])]
        if not re.fullmatch(r'\d{4}', cells[0]) or not re.fullmatch(r'[1-9]\d*', cells[1]):
            raise ValueError('Unsupported report-side source row')
        key = (cells[0], int(cells[1]))
        if key in result:
            raise ValueError('Ambiguous report-side source/regime')
        result[key] = cells
    if not result:
        raise ValueError('Empty report-side source table')
    return result


def check_source(values, table, parse_number):
    key = (values[0][-4:], int(values[1]))
    if key not in table:
        raise ValueError('Source missing from report-side source table')
    row = table[key]
    if values[2] == 'P' and row[2] != 'Т':
        raise ValueError('Input/report source type mismatch')
    # Only parameters relevant to Cm/Um/Xm. Coordinates and field-specific
    # settings need separate validation before any spatial equivalence claim.
    for index in PARAMETERS:
        actual = parse_number(values[index])
        if index == 4 and row[index] == '':
            if actual != 0:
                raise ValueError('Input/report source parameter mismatch: H2')
            continue
        expected = parse_number(row[index])
        with localcontext() as ctx:
            ctx.prec = 800
            half_step = Decimal(10) ** expected.as_tuple().exponent / 2
            if abs(actual - expected) > half_step:
                raise ValueError('Input/report source parameter mismatch: ' + HEADERS[index])
