from __future__ import annotations

from sympy.parsing.sympy_parser import parse_expr


def parse_expression(expression: str):
    return parse_expr(expression)
