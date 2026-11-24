"""Closed AST grammar for policy conditions (kernel-canonical evaluator).

Same security contract as backend hook_service.evaluate_condition, ported so
the SDK kernel has zero backend imports (single-source target P2-9: backend
delegates here). No Call nodes, no dunders, SyntaxError caught. Names resolve
only against the provided context.
"""

from __future__ import annotations

import ast
import operator
from typing import Any


class UnsafeExpressionError(Exception):
    """Raised when an expression contains disallowed constructs."""


_ALLOWED_COMPARE_OPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}

_ALLOWED_BOOL_OPS = {ast.And: all, ast.Or: any}
_ALLOWED_UNARY_OPS = {ast.Not: operator.not_}


def _eval_node(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in context:
            return context[node.id]
        raise UnsafeExpressionError(f"Unknown variable: {node.id}")
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_eval_node(e, context) for e in node.elts]
    if isinstance(node, ast.Subscript):
        value = _eval_node(node.value, context)
        sl = node.slice
        idx = sl.value if isinstance(sl, ast.Constant) else _eval_node(sl, context)
        try:
            return value[idx]
        except (KeyError, IndexError, TypeError) as e:
            raise UnsafeExpressionError(f"Bad subscript: {e}") from e
    if isinstance(node, ast.Attribute):
        if node.attr.startswith("_"):
            raise UnsafeExpressionError(f"Dunder/private attribute blocked: {node.attr}")
        return getattr(_eval_node(node.value, context), node.attr)
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, context)
        for op_node, comparator in zip(node.ops, node.comparators, strict=False):
            op_cls = type(op_node)
            if op_cls not in _ALLOWED_COMPARE_OPS:
                raise UnsafeExpressionError(f"Disallowed operator: {op_cls.__name__}")
            right = _eval_node(comparator, context)
            try:
                ok = _ALLOWED_COMPARE_OPS[op_cls](left, right)
            except TypeError as e:
                raise UnsafeExpressionError(f"Incomparable operands: {e}") from e
            if not ok:
                return False
            left = right
        return True
    if isinstance(node, ast.BoolOp):
        op_cls = type(node.op)
        if op_cls not in _ALLOWED_BOOL_OPS:
            raise UnsafeExpressionError(f"Disallowed bool op: {op_cls.__name__}")
        return _ALLOWED_BOOL_OPS[op_cls]([_eval_node(v, context) for v in node.values])
    if isinstance(node, ast.UnaryOp):
        op_cls = type(node.op)
        if op_cls not in _ALLOWED_UNARY_OPS:
            raise UnsafeExpressionError(f"Disallowed unary op: {op_cls.__name__}")
        return _ALLOWED_UNARY_OPS[op_cls](_eval_node(node.operand, context))
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, context)
    raise UnsafeExpressionError(
        f"Disallowed AST node: {type(node).__name__}. "
        "Comparisons, boolean ops, variables, constants, subscripts only."
    )


def evaluate_condition(expr: str, context: dict[str, Any]) -> bool:
    """Safely evaluate a condition. Raises UnsafeExpressionError on violation."""
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise UnsafeExpressionError(f"Syntax error: {e}") from e
    return bool(_eval_node(tree, context))
