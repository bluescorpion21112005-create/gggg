"""A small, safe Sigma evaluator for log files (no aggregation, no external backends).

Supported:
- selections: a keyword list (case-insensitive substring of the whole event), a field map
  (all fields must match), or a list of field maps (any).
- field modifiers: contains, startswith, endswith, re, all; plain values support * and ? wildcards.
- conditions: names, and / or / not, parentheses, `1 of X*`, `all of X*`, `1 of them`, `all of them`.
Rules using anything else (e.g. `| count()` aggregations) are refused at load time, never half-run.

Events are dicts (JSON-lines logs) or plain strings (one log line); field selections only match dicts.
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Union

import yaml

Event = Union[str, Dict[str, Any]]
LEVELS = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}
MAX_LINE = 64 * 1024


class SigmaError(ValueError):
    pass


def _wildcard(value: str) -> re.Pattern:
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def _value_matcher(raw: Any, mods: List[str]) -> Callable[[str], bool]:
    if raw is None:
        return lambda s: s == ""
    text = str(raw)
    if "re" in mods:
        try:
            rx = re.compile(text)
        except re.error as exc:
            raise SigmaError(f"bad regex {text!r}") from exc
        return lambda s: rx.search(s) is not None
    low = text.lower()
    if "contains" in mods:
        return lambda s: low in s.lower()
    if "startswith" in mods:
        return lambda s: s.lower().startswith(low)
    if "endswith" in mods:
        return lambda s: s.lower().endswith(low)
    if any(c in text for c in "*?"):
        rx = _wildcard(text)
        return lambda s: rx.match(s) is not None
    return lambda s: s.lower() == low


def _event_text(event: Event) -> str:
    return event if isinstance(event, str) else json.dumps(event, ensure_ascii=False, default=str)


def _field_value(event: Dict[str, Any], name: str) -> Optional[str]:
    cur: Any = event
    for part in name.split("."):                      # nested JSON: a.b.c
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return "" if cur is None else str(cur)


def _compile_map(spec: Dict[str, Any]) -> Callable[[Event], bool]:
    checks = []
    for key, raw in spec.items():
        field, *mods = str(key).split("|")
        unknown = set(mods) - MODIFIERS
        if unknown:
            raise SigmaError(f"unsupported modifier {sorted(unknown)}")
        values = raw if isinstance(raw, list) else [raw]
        matchers = [_value_matcher(v, mods) for v in values]
        need_all = "all" in mods

        def check(event, field=field, matchers=matchers, need_all=need_all):
            if not isinstance(event, dict):
                return False
            value = _field_value(event, field)
            if value is None:
                return any(m("") for m in matchers) and not need_all
            hits = (m(value) for m in matchers)
            return all(hits) if need_all else any(hits)
        checks.append(check)
    return lambda event: all(c(event) for c in checks)


def _compile_selection(spec: Any) -> Callable[[Event], bool]:
    if isinstance(spec, dict):
        return _compile_map(spec)
    if isinstance(spec, list) and spec and all(isinstance(x, dict) for x in spec):
        maps = [_compile_map(x) for x in spec]
        return lambda event: any(m(event) for m in maps)
    if isinstance(spec, list) and all(isinstance(x, (str, int, float)) for x in spec):
        words = [str(x).lower() for x in spec]
        return lambda event: any(w in _event_text(event).lower() for w in words)
    if isinstance(spec, (str, int)):
        word = str(spec).lower()
        return lambda event: word in _event_text(event).lower()
    raise SigmaError("unsupported selection")


class _Condition:
    TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")

    def __init__(self, text: str, selections: Dict[str, Callable[[Event], bool]]):
        if "|" in text:
            raise SigmaError("aggregations are not supported")
        self.sel = selections
        self.tokens = self._tokenize(text)
        self.pos = 0
        self.fn = self._or()
        if self.pos != len(self.tokens):
            raise SigmaError(f"unexpected token {self.tokens[self.pos]!r}")

    def _tokenize(self, text):
        out, i = [], 0
        while i < len(text):
            m = self.TOKEN.match(text, i)
            if not m:
                if text[i:].strip():
                    raise SigmaError(f"bad condition near {text[i:]!r}")
                break
            out.append(m.group(1))
            i = m.end()
        return out

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self):
        tok = self._peek()
        if tok is None:
            raise SigmaError("condition ended early")
        self.pos += 1
        return tok

    def _or(self):
        parts = [self._and()]
        while self._peek() == "or":
            self._take()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda e, p=parts: any(f(e) for f in p))

    def _and(self):
        parts = [self._not()]
        while self._peek() == "and":
            self._take()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda e, p=parts: all(f(e) for f in p))

    def _not(self):
        if self._peek() == "not":
            self._take()
            inner = self._not()
            return lambda e: not inner(e)
        return self._atom()

    def _group(self, pattern: str):
        names = list(self.sel) if pattern == "them" else [n for n in self.sel if fnmatch.fnmatchcase(n, pattern)]
        if not names:
            raise SigmaError(f"no selection matches {pattern!r}")
        return [self.sel[n] for n in names]

    def _atom(self):
        tok = self._take()
        if tok == "(":
            fn = self._or()
            if self._take() != ")":
                raise SigmaError("missing )")
            return fn
        if tok in ("1", "all", "any") and self._peek() == "of":
            self._take()
            group = self._group(self._take())
            return (lambda e, g=group: all(f(e) for f in g)) if tok == "all" else (lambda e, g=group: any(f(e) for f in g))
        if tok not in self.sel:
            raise SigmaError(f"unknown selection {tok!r}")
        return self.sel[tok]


@dataclass
class SigmaRule:
    name: str
    title: str
    severity: str
    match: Callable[[Event], bool]

    @classmethod
    def parse(cls, name: str, text: str) -> "SigmaRule":
        doc = yaml.safe_load(text)
        if not isinstance(doc, dict) or not isinstance(doc.get("detection"), dict):
            raise SigmaError("no detection")
        detection = dict(doc["detection"])
        condition = detection.pop("condition", None)
        detection.pop("timeframe", None)
        if isinstance(condition, list):
            condition = " or ".join(f"({c})" for c in condition)
        if not isinstance(condition, str):
            raise SigmaError("no condition")
        selections = {k: _compile_selection(v) for k, v in detection.items()}
        return cls(name=name, title=str(doc.get("title") or name)[:200],
                   severity=LEVELS.get(str(doc.get("level", "medium")), "medium"),
                   match=_Condition(condition, selections).fn)


def parse_event(line: str) -> Event:
    line = line.rstrip("\r\n")[:MAX_LINE]
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                return obj
        except ValueError:
            pass
    return line


def scan_lines(rules: List[SigmaRule], lines: Iterable[str], max_lines: int = 500_000) -> Dict[str, Dict[str, Any]]:
    """rule name → {rule, title, severity, count, line (first match)}."""
    hits: Dict[str, Dict[str, Any]] = {}
    for i, line in enumerate(lines):
        if i >= max_lines:
            break
        event = parse_event(line)
        for rule in rules:
            if rule.match(event):
                hit = hits.setdefault(rule.name, {"rule": rule.name, "title": rule.title, "severity": rule.severity,
                                                  "count": 0, "line": _event_text(event)[:500]})
                hit["count"] += 1
    return hits
