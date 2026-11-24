"""Tree-sitter wrapper for TypeScript / JavaScript parsing.

Provides a high-level API over raw tree-sitter nodes so that policy
rules and BOM extractors can query TS/JS ASTs without coupling to
tree-sitter internals.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Generator

try:
    import tree_sitter_javascript as _ts_js
    import tree_sitter_typescript as _ts_ts
    from tree_sitter import Language, Node, Parser, Tree
    _TS_IMPORT_ERROR: ImportError | None = None
except ImportError as _exc:
    _ts_js = None  # type: ignore[assignment]
    _ts_ts = None  # type: ignore[assignment]
    Language = Node = Parser = Tree = None  # type: ignore[assignment,misc]
    _TS_IMPORT_ERROR = _exc

# ---------------------------------------------------------------------------
# Data structures returned by high-level queries
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TSImport:
    """A single ES import statement."""

    module: str
    names: list[str] = field(default_factory=list)
    is_default: bool = False
    is_namespace: bool = False
    line: int = 0


@dataclass(frozen=True, slots=True)
class TSCall:
    """A function / method call site."""

    name: str
    full_name: str  # e.g. "fs.readFileSync"
    args_text: str  # raw source of the argument list
    line: int = 0


@dataclass(frozen=True, slots=True)
class TSStringLiteral:
    """A string literal (single-quoted, double-quoted, or template)."""

    value: str
    line: int = 0
    is_template: bool = False


@dataclass(frozen=True, slots=True)
class TSVarDecl:
    """A variable / constant declaration."""

    name: str
    kind: str  # "const" | "let" | "var"
    init_text: str  # raw source of the initialiser (RHS)
    line: int = 0


@dataclass(frozen=True, slots=True)
class TSClassDecl:
    """A class declaration."""

    name: str
    bases: list[str] = field(default_factory=list)
    line: int = 0


@dataclass(frozen=True, slots=True)
class TSProperty:
    """A property assignment inside an object literal."""

    key: str
    value_text: str
    line: int = 0


# ---------------------------------------------------------------------------
# Language helpers
# ---------------------------------------------------------------------------

_TS_EXTS = frozenset({".ts", ".mts", ".cts"})
_TSX_EXTS = frozenset({".tsx"})
_JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".jsx"})


def _ext_of(path: str) -> str:
    return PurePosixPath(path).suffix.lower()


# ---------------------------------------------------------------------------
# Parser singleton
# ---------------------------------------------------------------------------


class TSParser:
    """High-level tree-sitter wrapper for TypeScript & JavaScript."""

    _instance: TSParser | None = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._ts_lang = Language(_ts_ts.language_typescript())
        self._tsx_lang = Language(_ts_ts.language_tsx())
        self._js_lang = Language(_ts_js.language())

    # -- singleton -----------------------------------------------------------

    @classmethod
    def instance(cls) -> TSParser:
        """Return (or create) the module-level singleton."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # -- parsing -------------------------------------------------------------

    def language_for(self, path: str) -> Language:
        """Pick the correct :class:`Language` for *path*."""
        ext = _ext_of(path)
        if ext in _TSX_EXTS:
            return self._tsx_lang
        if ext in _TS_EXTS:
            return self._ts_lang
        return self._js_lang

    def parse(self, source: str | bytes, path: str = "file.ts") -> Tree:
        """Parse *source* and return the tree-sitter :class:`Tree`."""
        if isinstance(source, str):
            source = source.encode("utf-8")
        lang = self.language_for(path)
        parser = Parser(lang)
        return parser.parse(source)

    # -- generic traversal ---------------------------------------------------

    @staticmethod
    def walk(node: Node) -> Generator[Node, None, None]:
        """Depth-first yield of *node* and all its descendants."""
        cursor = node.walk()
        reached_root = False
        while not reached_root:
            yield cursor.node  # type: ignore[misc]
            if cursor.goto_first_child():
                continue
            if cursor.goto_next_sibling():
                continue
            retracing = True
            while retracing:
                if not cursor.goto_parent():
                    retracing = False
                    reached_root = True
                elif cursor.goto_next_sibling():
                    retracing = False

    @staticmethod
    def children_of_type(node: Node, *types: str) -> list[Node]:
        """Return direct children whose ``type`` is in *types*."""
        return [c for c in node.children if c.type in types]

    # -- high-level queries --------------------------------------------------

    def find_imports(self, tree: Tree) -> list[TSImport]:
        """Extract all ES ``import`` statements from *tree*."""
        results: list[TSImport] = []
        for node in self.walk(tree.root_node):
            if node.type != "import_statement":
                continue
            module = self._import_source(node)
            if module is None:
                continue
            names, is_default, is_ns = self._import_names(node)
            results.append(
                TSImport(
                    module=module,
                    names=names,
                    is_default=is_default,
                    is_namespace=is_ns,
                    line=node.start_point[0] + 1,
                )
            )
        return results

    def find_require_calls(self, tree: Tree) -> list[TSImport]:
        """Extract CommonJS ``require('...')`` calls as :class:`TSImport`."""
        results: list[TSImport] = []
        for node in self.walk(tree.root_node):
            if node.type != "call_expression":
                continue
            fn = node.child_by_field_name("function")
            if fn is None or self._text(fn) != "require":
                continue
            args = node.child_by_field_name("arguments")
            if args is None:
                continue
            for arg in args.children:
                if arg.type == "string":
                    mod = self._unquote(self._text(arg))
                    results.append(TSImport(module=mod, line=node.start_point[0] + 1))
        return results

    def find_function_calls(self, tree: Tree) -> list[TSCall]:
        """Find all call expressions in *tree*."""
        results: list[TSCall] = []
        for node in self.walk(tree.root_node):
            if node.type != "call_expression":
                continue
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                continue
            name = self._call_name(fn_node)
            full_name = self._text(fn_node)
            args_node = node.child_by_field_name("arguments")
            args_text = self._text(args_node) if args_node else ""
            results.append(
                TSCall(
                    name=name,
                    full_name=full_name,
                    args_text=args_text,
                    line=node.start_point[0] + 1,
                )
            )
        return results

    def find_new_expressions(self, tree: Tree) -> list[TSCall]:
        """Find all ``new Foo(...)`` expressions."""
        results: list[TSCall] = []
        for node in self.walk(tree.root_node):
            if node.type != "new_expression":
                continue
            constructor = node.child_by_field_name("constructor")
            if constructor is None:
                continue
            name = self._text(constructor)
            args_node = node.child_by_field_name("arguments")
            args_text = self._text(args_node) if args_node else ""
            results.append(
                TSCall(
                    name=name,
                    full_name=name,
                    args_text=args_text,
                    line=node.start_point[0] + 1,
                )
            )
        return results

    def find_string_literals(self, tree: Tree) -> list[TSStringLiteral]:
        """Return every string literal (including template literals)."""
        results: list[TSStringLiteral] = []
        for node in self.walk(tree.root_node):
            if node.type == "string":
                results.append(
                    TSStringLiteral(
                        value=self._unquote(self._text(node)),
                        line=node.start_point[0] + 1,
                    )
                )
            elif node.type == "template_string":
                results.append(
                    TSStringLiteral(
                        value=self._text(node),
                        line=node.start_point[0] + 1,
                        is_template=True,
                    )
                )
        return results

    def find_template_literals(self, tree: Tree) -> list[TSStringLiteral]:
        """Return only template literals (backtick strings)."""
        return [s for s in self.find_string_literals(tree) if s.is_template]

    def find_variable_declarations(self, tree: Tree) -> list[TSVarDecl]:
        """Extract top-level and nested variable declarations."""
        results: list[TSVarDecl] = []
        for node in self.walk(tree.root_node):
            if node.type in ("lexical_declaration", "variable_declaration"):
                kind = self._text(node).split()[0]  # const / let / var
                for decl in self.children_of_type(node, "variable_declarator"):
                    name_node = decl.child_by_field_name("name")
                    value_node = decl.child_by_field_name("value")
                    if name_node is not None:
                        results.append(
                            TSVarDecl(
                                name=self._text(name_node),
                                kind=kind,
                                init_text=self._text(value_node) if value_node else "",
                                line=decl.start_point[0] + 1,
                            )
                        )
        return results

    def find_class_declarations(self, tree: Tree) -> list[TSClassDecl]:
        """Find class declarations and their heritage (extends/implements)."""
        results: list[TSClassDecl] = []
        for node in self.walk(tree.root_node):
            if node.type != "class_declaration":
                continue
            name_node = node.child_by_field_name("name")
            if name_node is None:
                continue
            bases: list[str] = []
            heritage = self._find_child(node, "class_heritage")
            if heritage is not None:
                for child in self.walk(heritage):
                    if child.type == "identifier" and child != heritage:
                        bases.append(self._text(child))
            results.append(
                TSClassDecl(
                    name=self._text(name_node),
                    bases=bases,
                    line=node.start_point[0] + 1,
                )
            )
        return results

    def find_object_properties(
        self, node: Node, *, recursive: bool = False,
    ) -> list[TSProperty]:
        """Extract key-value pairs from an object literal *node*.

        If *recursive* is ``True``, also descend into nested objects.
        """
        results: list[TSProperty] = []
        iterator = self.walk(node) if recursive else iter(node.children)
        for child in iterator:
            if child.type in ("pair", "property_assignment"):
                key_node = child.child_by_field_name("key")
                val_node = child.child_by_field_name("value")
                if key_node is not None and val_node is not None:
                    results.append(
                        TSProperty(
                            key=self._text(key_node),
                            value_text=self._text(val_node),
                            line=child.start_point[0] + 1,
                        )
                    )
            elif child.type == "shorthand_property_identifier_pattern":
                results.append(
                    TSProperty(
                        key=self._text(child),
                        value_text=self._text(child),
                        line=child.start_point[0] + 1,
                    )
                )
        return results

    # -- private helpers -----------------------------------------------------

    @staticmethod
    def _text(node: Node | None) -> str:
        if node is None:
            return ""
        return node.text.decode("utf-8") if isinstance(node.text, bytes) else str(node.text)

    @staticmethod
    def _unquote(s: str) -> str:
        if len(s) >= 2 and s[0] in ('"', "'", "`") and s[-1] == s[0]:
            return s[1:-1]
        return s

    def _import_source(self, node: Node) -> str | None:
        src = node.child_by_field_name("source")
        if src is not None:
            return self._unquote(self._text(src))
        for child in node.children:
            if child.type == "string":
                return self._unquote(self._text(child))
        return None

    def _import_names(self, node: Node) -> tuple[list[str], bool, bool]:
        names: list[str] = []
        is_default = False
        is_namespace = False
        for child in node.children:
            if child.type == "import_clause":
                for cc in child.children:
                    if cc.type == "identifier":
                        names.append(self._text(cc))
                        is_default = True
                    elif cc.type == "named_imports":
                        for spec in cc.children:
                            if spec.type == "import_specifier":
                                name_node = spec.child_by_field_name("name")
                                if name_node:
                                    names.append(self._text(name_node))
                    elif cc.type == "namespace_import":
                        is_namespace = True
                        for sub in cc.children:
                            if sub.type == "identifier":
                                names.append(self._text(sub))
        return names, is_default, is_namespace

    def _call_name(self, fn_node: Node) -> str:
        """Return the short name of a call (e.g. ``readFileSync``)."""
        if fn_node.type == "identifier":
            return self._text(fn_node)
        if fn_node.type == "member_expression":
            prop = fn_node.child_by_field_name("property")
            if prop is not None:
                return self._text(prop)
        return self._text(fn_node)

    @staticmethod
    def _find_child(node: Node, child_type: str) -> Node | None:
        for c in node.children:
            if c.type == child_type:
                return c
        return None
