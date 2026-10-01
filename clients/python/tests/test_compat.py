"""The package promises Python 3.10. These parse every module with the 3.10
grammar, which catches syntax a newer interpreter accepts and 3.10 does not
(``except*``, type parameter lists, and the like), and look for the one change
that grammar check cannot see: from 3.12 a replacement field inside an f-string
may reuse the f-string's own quotes. Neither can see a call to a newer
standard-library function."""

from __future__ import annotations

import ast
import io
import pathlib
import sys
import tokenize
import unittest
from typing import List

PACKAGE = pathlib.Path(__file__).resolve().parent.parent / "src" / "plimsoll_client"


def _delimiter(token: str) -> str:
    body = token.lstrip("rRbBfFuU")
    return body[:3] if body[:3] in ('"""', "'''") else body[:1]


class Python310(unittest.TestCase):
    def modules(self) -> List[pathlib.Path]:
        found = sorted(PACKAGE.glob("*.py"))
        self.assertGreater(len(found), 5)
        return found

    def test_grammar(self) -> None:
        for path in self.modules():
            with self.subTest(path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 10))

    def test_no_fstring_reuses_its_quotes(self) -> None:
        if sys.version_info < (3, 12):
            return  # the interpreter running this would have refused the import
        start, end = getattr(tokenize, "FSTRING_START"), getattr(tokenize, "FSTRING_END")
        for path in self.modules():
            outer: List[str] = []
            src = path.read_text(encoding="utf-8")
            for tok in tokenize.generate_tokens(io.StringIO(src).readline):
                if tok.type in (start, tokenize.STRING) and outer:
                    inner = _delimiter(tok.string)
                    with self.subTest(path.name, line=tok.start[0]):
                        self.assertFalse(
                            inner == outer[-1] or (len(outer[-1]) == 1 and inner[0] == outer[-1]),
                            "an f-string reuses its own quotes inside a replacement field",
                        )
                if tok.type == start:
                    outer.append(_delimiter(tok.string))
                elif tok.type == end:
                    outer.pop()


if __name__ == "__main__":
    unittest.main()
