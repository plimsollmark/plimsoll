"""Writes tasks.json: ten Python tasks for the Nemotron agent batch.

Each task is a written spec, a few visible examples (in the spec text) and hidden cases.
Every hidden case's expected value is computed here by a reference solution, and every
case follows from the spec text alone: the grammar or rule is stated, not implied. A
handful of expectations are also written out by hand below and must agree with the
reference, so a wrong reference fails this script instead of the agents.

    python3 make_tasks.py   # writes tasks.json beside this file
"""
import copy
import datetime
import json
import os
import re

TASKS = []
RAISES = object()


def task(tid, title, function, spec, ref, cases, unchanged=False):
    rows = []
    for args in cases:
        try:
            got = ref(*copy.deepcopy(args))
            rows.append({"args": args, "expect": got})
        except ValueError:
            rows.append({"args": args, "raises": "ValueError"})
    TASKS.append({"id": tid, "title": title, "function": function, "spec": spec,
                  "unchanged": unchanged, "cases": rows})


def expect(fn, args, want):
    try:
        got = fn(*copy.deepcopy(args))
    except ValueError:
        got = RAISES
    assert got == want or (want is not RAISES and got is not RAISES and type(want) is float and abs(got - want) < 1e-9), (fn.__name__, args, got, want)


# 1. ISO 8601 durations ---------------------------------------------------------------
_N = r"([0-9]+(?:\.[0-9]+)?)"


def iso_duration_seconds(s):
    if not isinstance(s, str):
        raise ValueError("not a string")
    m = re.fullmatch("P" + _N + "W", s)
    if m:
        return float(m.group(1)) * 7 * 86400
    m = re.fullmatch("P(?:" + _N + "D)?(T(?:" + _N + "H)?(?:" + _N + "M)?(?:" + _N + "S)?)?", s)
    if not m:
        raise ValueError("not a duration")
    d, t, h, mi, sec = m.groups()
    if t is not None and h is None and mi is None and sec is None:
        raise ValueError("T with nothing after it")
    if d is None and h is None and mi is None and sec is None:
        raise ValueError("no count")
    return sum(float(v) * k for v, k in ((d, 86400), (h, 3600), (mi, 60), (sec, 1)) if v is not None)


task("iso-duration", "ISO 8601 durations to seconds", "iso_duration_seconds",
     'Write a Python function iso_duration_seconds(s) that converts an ISO 8601 duration string to a number '
     'of seconds (a float). The accepted forms are exactly these: "P", then a week count, then "W", and nothing '
     'else (for example "P2W"); or "P", then an optional day count and "D", then optionally "T" followed by at '
     'least one of an hour count with "H", a minute count with "M" and a second count with "S", in that order. '
     'At least one count must be present. A count is one or more ASCII digits, optionally followed by "." and '
     'one or more ASCII digits. Letters are uppercase. 1 week = 7 days and 1 day = 86400 seconds. Any other '
     'string, including years ("Y"), months ("M" before "T"), lowercase letters, spaces and signs, must raise '
     'ValueError. Examples: "PT0S" -> 0, "PT1H30M" -> 5400, "P1DT2H" -> 93600, "P1W" -> 604800, '
     '"PT0.5S" -> 0.5, "P2DT3H4M5.25S" -> 183845.25; "", "P", "PT", "1H" and "P1H" raise ValueError.',
     iso_duration_seconds,
     [[x] for x in ["PT0S", "PT1H30M", "P1DT2H", "P1W", "PT0.5S", "P2DT3H4M5.25S", "", "P", "PT", "1H", "P1H",
                    "P1Y", "P1M", "P2W", "P1W2D", "P1DT", "PT1M30S", "P0D", "pt1s", " PT1S", "PT1.5M", "PT1S1M",
                    "P3DT4H", "PT36H", "PT1.S", "PT.5S", "P1.5D", "-PT1S", "PT1S\n", "PT١S"]])
expect(iso_duration_seconds, ["PT1H30M"], 5400.0)
expect(iso_duration_seconds, ["P1W2D"], RAISES)
expect(iso_duration_seconds, ["P1DT"], RAISES)
expect(iso_duration_seconds, ["PT1S\n"], RAISES)
expect(iso_duration_seconds, ["P1.5D"], 129600.0)


# 2. Roman numerals ------------------------------------------------------------------
def _to_roman(n):
    out = ""
    for one, five, ten, unit in (("M", "", "", 1000), ("C", "D", "M", 100), ("X", "L", "C", 10), ("I", "V", "X", 1)):
        d = n // unit % 10 if unit < 1000 else n // 1000
        out += ["", one, one * 2, one * 3, one + five, five, five + one, five + one * 2, five + one * 3, one + ten][d]
    return out


_ROMAN = {_to_roman(n): n for n in range(1, 4000)}


def from_roman(s):
    if not isinstance(s, str) or s not in _ROMAN:
        raise ValueError("not a standard Roman numeral")
    return _ROMAN[s]


task("from-roman", "Strict Roman numerals", "from_roman",
     'Write a Python function from_roman(s) that converts a Roman numeral to an int. Accept only the standard '
     'form of a number from 1 to 3999, using I=1, V=5, X=10, L=50, C=100, D=500, M=1000: the thousands, '
     'hundreds, tens and units digits are written in that order, a zero digit is written as nothing, and each '
     'other digit d is written with that place\'s one-symbol (I, X, C or M), five-symbol (V, L or D) and the '
     'next place\'s one-symbol: 1 to 3 as that many one-symbols, 4 as one-symbol then five-symbol (IV, XL, CD), '
     '5 as the five-symbol, 6 to 8 as the five-symbol then 1 to 3 one-symbols, 9 as one-symbol then the next '
     'place\'s one-symbol (IX, XC, CM); thousands are 1 to 3 M. Uppercase only. Any other string, including the '
     'empty string, must raise ValueError. Examples: "III" -> 3, "IV" -> 4, "IX" -> 9, "LVIII" -> 58, '
     '"MCMXCIV" -> 1994; "IIII", "IC" and "" raise ValueError.',
     from_roman,
     [[x] for x in ["III", "IV", "IX", "LVIII", "MCMXCIV", "IIII", "IC", "", "MMMCMXCIX", "XLIX", "CD", "I",
                    "MMMM", "VX", "IL", "mcm", "DCD", "VV", "XXXX", "IIV", "MCM ", "MCM\n", "CM", "XCIX", "IVI",
                    "N", "MMXXVI", "LXL"]])
expect(from_roman, ["MCMXCIV"], 1994)
expect(from_roman, ["MMMCMXCIX"], 3999)
expect(from_roman, ["IVI"], RAISES)
expect(from_roman, ["XXXX"], RAISES)


# 3. Semantic versions ---------------------------------------------------------------
_IDENT = re.compile(r"[0-9A-Za-z-]+")
_NUM = re.compile(r"0|[1-9][0-9]*")


def _parse_semver(v):
    if not isinstance(v, str):
        raise ValueError("not a string")
    core, plus, build = v.partition("+")
    if plus and not all(_IDENT.fullmatch(x) for x in build.split(".")):
        raise ValueError("bad build metadata")
    core, dash, pre = core.partition("-")
    parts = core.split(".")
    if len(parts) != 3 or not all(_NUM.fullmatch(p) for p in parts):
        raise ValueError("bad core")
    ids = []
    if dash:
        for x in pre.split("."):
            if not _IDENT.fullmatch(x):
                raise ValueError("bad pre-release")
            if x.isdigit() and not _NUM.fullmatch(x):
                raise ValueError("leading zero")
            ids.append(x)
    return tuple(int(p) for p in parts), ids, bool(dash)


def semver_compare(a, b):
    (ca, ia, pa), (cb, ib, pb) = _parse_semver(a), _parse_semver(b)
    if ca != cb:
        return -1 if ca < cb else 1
    if pa != pb:
        return -1 if pa else 1
    for x, y in zip(ia, ib):
        if x == y:
            continue
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            return -1 if int(x) < int(y) else 1
        if xn != yn:
            return -1 if xn else 1
        return -1 if x < y else 1
    return (len(ia) > len(ib)) - (len(ia) < len(ib))


_chain = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
          "1.0.0-rc.1", "1.0.0"]
task("semver", "Semantic version precedence", "semver_compare",
     'Write a Python function semver_compare(a, b) that compares two Semantic Versioning 2.0.0 version strings '
     'and returns -1 if a has lower precedence than b, 0 if equal precedence and 1 if higher. A version is '
     'MAJOR.MINOR.PATCH, each a non-negative integer written without leading zeros ("0" is fine, "01" is not), '
     'optionally followed by "-" and a pre-release, then optionally by "+" and build metadata. The pre-release '
     'and the build metadata are each one or more dot-separated identifiers; an identifier is non-empty and made '
     'only of ASCII letters, ASCII digits and "-"; a pre-release identifier made only of digits must not have a '
     'leading zero. Precedence: compare MAJOR, MINOR and PATCH numerically; a version with a pre-release is lower '
     'than the same version without one; two pre-releases compare identifier by identifier from the left: two '
     'all-digit identifiers numerically, two others in ASCII order, and an all-digit identifier is lower than '
     'any other; if every shared identifier is equal, the one with more identifiers is higher. Build metadata is '
     'ignored. An invalid version string must raise ValueError. Examples: ("1.0.0", "2.0.0") -> -1, '
     '("2.1.1", "2.1.0") -> 1, ("1.0.0-alpha", "1.0.0") -> -1, ("1.0.0-alpha.1", "1.0.0-alpha.beta") -> -1, '
     '("1.0.0+build.5", "1.0.0") -> 0; ("1.0", "1.0.0") and ("01.0.0", "1.0.0") raise ValueError.',
     semver_compare,
     [["1.0.0", "2.0.0"], ["2.1.1", "2.1.0"], ["1.0.0-alpha", "1.0.0"], ["1.0.0-alpha.1", "1.0.0-alpha.beta"],
      ["1.0.0+build.5", "1.0.0"], ["1.0", "1.0.0"], ["01.0.0", "1.0.0"]]
     + [[x, y] for x, y in zip(_chain, _chain[1:])] + [[y, x] for x, y in zip(_chain, _chain[1:])]
     + [["1.0.0-alpha", "1.0.0-alpha"], ["1.0.0-01", "1.0.0"], ["1.0.0-", "1.0.0"], ["1.0.0+", "1.0.0"],
        ["1.0.0-a..b", "1.0.0"], ["1.0.0-rc.1+build.1", "1.0.0-rc.1+build.2"], ["1.10.0", "1.9.0"],
        ["1.0.0-0A", "1.0.0-0"], ["1.0.0-alpha-1", "1.0.0-alpha"], ["v1.0.0", "1.0.0"], [" 1.0.0", "1.0.0"],
        ["1.0.0-ß", "1.0.0"], ["1.0.0+build.01", "1.0.0"], ["1.2.3-alpha.10", "1.2.3-alpha.9"],
        ["1.0.0", "1.0.0-x"], ["0.0.0", "0.0.0-0"], ["1.0.0-1", "1.0.0-a"]])
expect(semver_compare, ["1.0.0-beta.11", "1.0.0-beta.2"], 1)
expect(semver_compare, ["1.0.0-0A", "1.0.0-0"], 1)
expect(semver_compare, ["1.0.0-01", "1.0.0"], RAISES)
expect(semver_compare, ["1.0.0+build.01", "1.0.0"], 0)
expect(semver_compare, ["1.0.0-alpha", "1.0.0-alpha.1"], -1)


# 4. Luhn ----------------------------------------------------------------------------
def luhn_valid(s):
    if not isinstance(s, str) or any(c not in "0123456789 " for c in s):
        return False
    digits = [int(c) for c in s if c != " "]
    if len(digits) < 2:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


task("luhn", "Luhn check digits", "luhn_valid",
     'Write a Python function luhn_valid(s) that returns True if s is a valid Luhn number and False otherwise. '
     's may contain ASCII digits and spaces; spaces are ignored. If s contains any other character, or has fewer '
     'than two digits once the spaces are removed, return False. The Luhn rule: starting from the rightmost '
     'digit, double every second digit (the second from the right, the fourth, and so on), subtracting 9 from '
     'any doubled value above 9; the number is valid when the sum of all the digits so treated is a multiple of '
     '10. Never raise for a string input. Examples: "4539 3195 0343 6467" -> True, "8273 1232 7352 0569" -> '
     'False, "059" -> True, "0" -> False, "055-444-285" -> False.',
     luhn_valid,
     [[x] for x in ["4539 3195 0343 6467", "8273 1232 7352 0569", "059", "0", "055-444-285", "055 444 285", " 0",
                    "0 0", "00", "091", "059a", "", "  ", "1", "79927398713", "79927398710",
                    "١٢٣", "4539\t3195", "095 245 88", "234 567 891 234", "18"]])
expect(luhn_valid, ["79927398713"], True)
expect(luhn_valid, ["0 0"], True)
expect(luhn_valid, ["١٢٣"], False)
expect(luhn_valid, ["18"], True)


# 5. Word wrap -----------------------------------------------------------------------
def wrap(text, width):
    if not isinstance(width, int) or isinstance(width, bool) or width < 1:
        raise ValueError("width must be at least 1")
    lines, line = [], ""
    for word in text.split():
        for piece in [word[i:i + width] for i in range(0, len(word), width)]:
            if line and len(line) + 1 + len(piece) <= width:
                line += " " + piece
            else:
                if line:
                    lines.append(line)
                line = piece
    if line:
        lines.append(line)
    return lines


task("wrap", "Greedy word wrap", "wrap",
     'Write a Python function wrap(text, width) that word-wraps text into a list of lines. Words are the runs of '
     'non-whitespace characters (what str.split() with no arguments returns). Fill lines greedily: a word joins '
     'the current line, after one space, if the line\'s length plus 1 plus the word\'s length is at most width; '
     'otherwise the current line is finished and the word starts the next line. A word longer than width is '
     'first cut into pieces of exactly width characters (the last piece may be shorter), and each piece is then '
     'placed as a word by the same rule, so further words may follow the last piece on its line. Lines never '
     'have leading or trailing spaces. Return [] when text has no words. If width is less than 1, raise '
     'ValueError. Examples: wrap("the quick brown fox", 10) -> ["the quick", "brown fox"], '
     'wrap("abcdefghij", 4) -> ["abcd", "efgh", "ij"], wrap("", 5) -> [], wrap("a b", 0) raises ValueError.',
     wrap,
     [["the quick brown fox", 10], ["abcdefghij", 4], ["", 5], ["a b", 0], ["   ", 5], ["a b", -1],
      ["hello world", 5], ["hello world", 11], ["a\tb\nc", 3], ["abcde f", 4], ["ab cdefgh", 4], ["x", 1],
      ["aa bb", 1], ["one  two", 3], ["hello world", 4], ["a bb ccc dddd", 6], ["  lead and trail  ", 9]])
expect(wrap, ["abcde f", 4], ["abcd", "e f"])
expect(wrap, ["hello world", 4], ["hell", "o", "worl", "d"])
expect(wrap, ["a\tb\nc", 3], ["a b", "c"])


# 6. Intervals -----------------------------------------------------------------------
def merge_intervals(intervals):
    for s, e in intervals:
        if s > e:
            raise ValueError("start after end")
    out = []
    for s, e in sorted(intervals):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


task("intervals", "Merging closed intervals", "merge_intervals",
     'Write a Python function merge_intervals(intervals) that takes a list of [start, end] pairs of integers '
     '(closed intervals, start <= end) in any order and returns a new list of merged pairs sorted by start. Two '
     'intervals merge when they overlap or touch: [1, 3] and [3, 5] merge to [1, 5]; [1, 2] and [3, 4] do not '
     'merge. Each returned pair is a list of two ints, not a tuple. Do not modify the input list or its pairs. '
     'If any pair has start > end, raise ValueError. Examples: [[1, 3], [2, 6], [8, 10], [15, 18]] -> '
     '[[1, 6], [8, 10], [15, 18]], [[1, 4], [4, 5]] -> [[1, 5]], [] -> [], [[3, 1]] raises ValueError.',
     merge_intervals,
     [[[[1, 3], [2, 6], [8, 10], [15, 18]]], [[[1, 4], [4, 5]]], [[]], [[[3, 1]]], [[[1, 2], [3, 4]]], [[[5, 5]]],
      [[[8, 10], [1, 3], [2, 6]]], [[[1, 10], [2, 3]]], [[[1, 4], [0, 4]]], [[[-5, -1], [-1, 2]]],
      [[[1, 2], [2, 3], [3, 4]]], [[[1, 5], [2, 3], [4, 8]]], [[[1, 2], [1, 2]]], [[[0, 0], [1, 1]]],
      [[[1, 2], [5, 4]]], [[[3, 4], [1, 2]]]],
     unchanged=True)
expect(merge_intervals, [[[0, 0], [1, 1]]], [[0, 0], [1, 1]])
expect(merge_intervals, [[[1, 4], [4, 5]]], [[1, 5]])


# 7. CSV -----------------------------------------------------------------------------
def parse_csv_line(line):
    fields, i, n = [], 0, len(line)
    while True:
        if i < n and line[i] == '"':
            i += 1
            buf = []
            while True:
                if i >= n:
                    raise ValueError("unterminated quote")
                if line[i] == '"':
                    if i + 1 < n and line[i + 1] == '"':
                        buf.append('"')
                        i += 2
                        continue
                    i += 1
                    break
                buf.append(line[i])
                i += 1
            fields.append("".join(buf))
            if i < n and line[i] != ",":
                raise ValueError("text after a closing quote")
        else:
            j = line.find(",", i)
            j = n if j < 0 else j
            if '"' in line[i:j]:
                raise ValueError("quote in an unquoted field")
            fields.append(line[i:j])
            i = j
        if i >= n:
            return fields
        i += 1  # the comma


task("csv-line", "One line of CSV", "parse_csv_line",
     'Write a Python function parse_csv_line(line) that splits one line of CSV into a list of field strings. '
     'Fields are separated by commas. A field whose first character is a double quote is quoted: it runs to its '
     'closing quote; inside it a comma is an ordinary character and two double quotes in a row stand for one '
     'double quote; the closing quote must be followed by a comma or the end of the line. Any other field is '
     'unquoted and must not contain a double quote. Spaces are ordinary characters and are kept. Raise '
     'ValueError for a double quote in an unquoted field, a quoted field with no closing quote, or anything but '
     'a comma after a closing quote. The empty line is one empty field. Examples: \'a,b,c\' -> [\'a\', \'b\', '
     '\'c\'], \'"a,b",c\' -> [\'a,b\', \'c\'], \'"say ""hi""",x\' -> [\'say "hi"\', \'x\'], \'\' -> [\'\'], '
     '\'a"b\' raises ValueError.',
     parse_csv_line,
     [[x] for x in ['a,b,c', '"a,b",c', '"say ""hi""",x', '', 'a"b', ',,', ' a , b ', '"",x', '"a"b', '"abc',
                    'a,"b', '"a""', '""""', 'a, "b"', 'x,', '"x",', '"a,b', '"a""b",""', 'a,b,']])
expect(parse_csv_line, ['""""'], ['"'])
expect(parse_csv_line, ['a, "b"'], RAISES)
expect(parse_csv_line, [',,'], ['', '', ''])
expect(parse_csv_line, ['"a""'], RAISES)


# 8. Business days -------------------------------------------------------------------
def _date(s):
    if not isinstance(s, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", s):
        raise ValueError("not YYYY-MM-DD")
    return datetime.date(int(s[:4]), int(s[5:7]), int(s[8:]))


def add_business_days(start, n, holidays):
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise ValueError("n must be an int >= 0")
    day, off = _date(start), {_date(h) for h in holidays}
    while n:
        day += datetime.timedelta(days=1)
        if day.weekday() < 5 and day not in off:
            n -= 1
    return day.isoformat()


task("business-days", "Adding business days", "add_business_days",
     'Write a Python function add_business_days(start, n, holidays) where start is a date string \'YYYY-MM-DD\', '
     'n is an int >= 0 and holidays is a list of \'YYYY-MM-DD\' strings. Business days are Monday to Friday, '
     'except holidays. Return, as a \'YYYY-MM-DD\' string, the date reached by moving forward from start one '
     'calendar day at a time, counting only business days, and stopping once n business days have been counted; '
     'start itself is never counted. When n is 0, return start unchanged, even if it is not a business day. '
     'Raise ValueError if n is negative or not an int (a bool is not an int here), or if start or any holiday is '
     'not a valid date written in exactly that format (four digits, a hyphen, two digits, a hyphen, two '
     'digits). Examples: add_business_days(\'2026-10-23\', 1, []) -> \'2026-10-26\' (a Friday to the next '
     'Monday), add_business_days(\'2026-10-23\', 1, [\'2026-10-26\']) -> \'2026-10-27\', '
     'add_business_days(\'2026-10-24\', 0, []) -> \'2026-10-24\'.',
     add_business_days,
     [["2026-10-23", 1, []], ["2026-10-23", 1, ["2026-10-26"]], ["2026-10-24", 0, []], ["2026-10-24", 1, []],
      ["2026-12-31", 1, ["2027-01-01"]], ["2026-10-23", 5, []], ["2026-10-23", -1, []], ["2026-02-30", 1, []],
      ["2026-1-05", 1, []], ["2026-10-23", 1, ["2026-13-01"]], ["2026-10-23", True, []], ["2026-10-23", 1.0, []],
      ["2024-02-28", 1, []], ["2026-10-23", 2, ["2026-10-24"]], ["20261023", 1, []], ["2026-10-23", 10, []],
      ["2026-10-23", 3, ["2026-10-26", "2026-10-27"]], ["2026-10-23 ", 1, []]])
expect(add_business_days, ["2026-12-31", 1, ["2027-01-01"]], "2027-01-04")
expect(add_business_days, ["2024-02-28", 1, []], "2024-02-29")
expect(add_business_days, ["20261023", 1, []], RAISES)
expect(add_business_days, ["2026-1-05", 1, []], RAISES)
expect(add_business_days, ["2026-10-23", 2, ["2026-10-24"]], "2026-10-27")


# 9. Numbers in words ----------------------------------------------------------------
_ONES = ("zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen "
         "sixteen seventeen eighteen nineteen").split()
_TENS = "_ _ twenty thirty forty fifty sixty seventy eighty ninety".split()


def _below_thousand(n):
    words = []
    if n >= 100:
        words.append(_ONES[n // 100] + " hundred")
        n %= 100
    if n >= 20:
        words.append(_TENS[n // 10] + ("-" + _ONES[n % 10] if n % 10 else ""))
    elif n:
        words.append(_ONES[n])
    return " ".join(words)


def number_to_words(n):
    if not isinstance(n, int) or isinstance(n, bool) or not 0 <= n <= 999999999:
        raise ValueError("out of range")
    if n == 0:
        return "zero"
    words = []
    for scale, name in ((1000000, " million"), (1000, " thousand"), (1, "")):
        group = n // scale % 1000
        if group:
            words.append(_below_thousand(group) + name)
    return " ".join(words)


task("number-words", "Numbers in English words", "number_to_words",
     'Write a Python function number_to_words(n) that writes an int from 0 to 999999999 in English words: '
     'lowercase, American style, never using "and". Zero to nineteen are single words (zero, one, ..., '
     'nineteen). Tens are twenty, thirty, forty, fifty, sixty, seventy, eighty, ninety, joined to a following '
     'unit by a hyphen (twenty-one). A hundreds digit is written "<unit> hundred", followed by a space and the '
     'rest when the rest is not zero. Thousands and millions are groups of three digits written the same way and '
     'followed by " thousand" or " million"; a group that is zero is left out. Words are separated by single '
     'spaces. Raise ValueError for an int outside the range and for anything that is not an int (a bool is not '
     'an int here). Examples: 0 -> \'zero\', 13 -> \'thirteen\', 21 -> \'twenty-one\', 105 -> \'one hundred '
     'five\', 1000 -> \'one thousand\', 1234567 -> \'one million two hundred thirty-four thousand five hundred '
     'sixty-seven\'.',
     number_to_words,
     [[x] for x in [0, 13, 21, 105, 1000, 1234567, 999999999, 1000000000, -1, 100, 110, 1000010, 1001000, 20, 40,
                    90000, 700000000, True, 5.0, 15, 1000001, 19019, 80080080]])
expect(number_to_words, [1234567], "one million two hundred thirty-four thousand five hundred sixty-seven")
expect(number_to_words, [1000010], "one million ten")
expect(number_to_words, [80080080], "eighty million eighty thousand eighty")
expect(number_to_words, [True], RAISES)


# 10. Balanced brackets --------------------------------------------------------------
def balanced(s):
    pairs, stack, i, n = {")": "(", "]": "[", "}": "{"}, [], 0, len(s)
    while i < n:
        c = s[i]
        if c in "'\"":
            i += 1
            while True:
                if i >= n:
                    return False
                if s[i] == "\\":
                    i += 2
                    continue
                if s[i] == c:
                    break
                i += 1
        elif c in "([{":
            stack.append(c)
        elif c in ")]}":
            if not stack or stack.pop() != pairs[c]:
                return False
        i += 1
    return not stack


task("brackets", "Balanced brackets around quoted strings", "balanced",
     'Write a Python function balanced(s) that returns True if the brackets (), [] and {} in s are balanced and '
     'properly nested, and False otherwise. Characters inside quoted strings are ignored: a quoted string starts '
     'at a single or double quote and ends at the next unescaped quote of the same kind; inside it, a backslash '
     'escapes the character after it, so a backslash then a quote does not end the string. Outside quoted '
     'strings a backslash is an ordinary character. A quoted string still open at the end of s makes the result '
     'False. All other characters are ignored. Examples: \'([]{})\' -> True, \'([)]\' -> False, \'f("(")\' -> '
     'True, \'"abc\' -> False, \'\' -> True.',
     balanced,
     [[x] for x in ['([]{})', '([)]', 'f("(")', '"abc', '', 'a(b)c', '(', ')(', '{[()()]}', '"\\""()',
                    "'(' + ')'", 'x = "it\\\'s"', "'\\'", '\\(', '"[" ]', "'\"'", '"a\\\\"(', "[']'",
                    '"\\\\"', "'a' [\"b\"]", '"\\']])
expect(balanced, ['"\\""()'], True)
expect(balanced, ["'\\'"], False)
expect(balanced, ['\\('], False)
expect(balanced, ['"a\\\\"('], False)
expect(balanced, ['"\\\\"'], True)

if __name__ == "__main__":
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tasks.json")
    with open(path, "w") as f:
        json.dump(TASKS, f, indent=1, ensure_ascii=True)
        f.write("\n")
    print(f"wrote {path}: {len(TASKS)} tasks, {sum(len(t['cases']) for t in TASKS)} cases")
