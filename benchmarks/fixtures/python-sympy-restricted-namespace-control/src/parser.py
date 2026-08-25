from __future__ import annotations

from sympy import Float, Integer, Rational, Symbol
from sympy.parsing.sympy_parser import parse_expr

SAFE_GLOBALS = {"__builtins__": {}}
SAFE_LOCALS = {"Float": Float, "Integer": Integer, "Rational": Rational, "Symbol": Symbol}


def parse_expression(expression: str):
    return parse_expr(expression, local_dict=SAFE_LOCALS, global_dict=SAFE_GLOBALS)
