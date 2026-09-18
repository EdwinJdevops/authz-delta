"""IAM string operators; shell character classes are deliberately unsupported."""

import re


def matches(value: str, operator: str, expected: str) -> bool:
    if operator == "StringEquals":
        return value == expected
    if operator == "StringLike":
        expression = re.escape(expected).replace(r"\*", ".*").replace(r"\?", ".")
        return re.fullmatch(expression, value, flags=re.DOTALL) is not None
    raise ValueError("unsupported IAM string operator")
