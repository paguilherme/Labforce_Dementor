"""Small lexical filter shared by source classification and governance metrics."""
import re

_LEXICAL = re.compile(r"'(?:\\.|[^'\\])*'|/\*.*?\*/|//[^\n]*", re.S)


def code_only(text: str) -> str:
    return _LEXICAL.sub(lambda match: "".join("\n" if c == "\n" else " " for c in match.group()), text)
