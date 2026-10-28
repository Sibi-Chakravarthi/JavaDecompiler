"""
callgraph.py — Lightweight intra-JAR call graph and entry-point reachability.

Builds caller-callee relationships across parsed classes and detects whether
methods or dangerous sinks are reachable from load-time entry points (<clinit>,
main, Java agents, ServiceLoader).
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from javadecompiler.class_parser import ClassInfo
from javadecompiler.security.rules.helpers import get_call_info


class CallGraph:
    """Inter-procedural call graph representing caller -> callee relationships."""

    def __init__(self) -> None:
        # (caller_class, caller_method) -> set of (callee_class, callee_method)
        self.edges: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
        # (callee_class, callee_method) -> set of (caller_class, caller_method)
        self.reverse_edges: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
        # Known entry points
        self.entry_points: Set[Tuple[str, str]] = set()

    def add_edge(
        self,
        caller: Tuple[str, str],
        callee: Tuple[str, str],
    ) -> None:
        self.edges.setdefault(caller, set()).add(callee)
        self.reverse_edges.setdefault(callee, set()).add(caller)

    def get_callees(self, class_name: str, method_name: str) -> List[Tuple[str, str]]:
        """Returns direct callees of the given method."""
        norm_cls = class_name.replace(".", "/")
        return sorted(list(self.edges.get((norm_cls, method_name), set())))

    def get_callers(self, class_name: str, method_name: str) -> List[Tuple[str, str]]:
        """Returns direct callers of the given method."""
        norm_cls = class_name.replace(".", "/")
        return sorted(list(self.reverse_edges.get((norm_cls, method_name), set())))

    def find_path(
        self,
        source: Tuple[str, str],
        target: Tuple[str, str],
        max_depth: int = 8,
    ) -> Optional[List[Tuple[str, str]]]:
        """Breadth-first search for a call path from source to target."""
        if source == target:
            return [source]

        queue: deque[List[Tuple[str, str]]] = deque([[source]])
        visited: Set[Tuple[str, str]] = {source}

        while queue:
            path = queue.popleft()
            if len(path) > max_depth:
                continue
            curr = path[-1]
            for callee in self.edges.get(curr, set()):
                if callee == target:
                    return path + [callee]
                if callee not in visited:
                    visited.add(callee)
                    queue.append(path + [callee])
        return None

    def is_reachable_from_entry(
        self,
        class_name: str,
        method_name: str,
        max_depth: int = 6,
    ) -> Tuple[bool, Optional[List[Tuple[str, str]]]]:
        """Checks if method is reachable from any known entry point (<clinit>, main, agents)."""
        target = (class_name.replace(".", "/"), method_name)
        for ep in self.entry_points:
            path = self.find_path(ep, target, max_depth=max_depth)
            if path:
                return True, path
        return False, None

    def is_reachable_from_clinit(
        self,
        class_name: str,
        method_name: str,
        max_depth: int = 6,
    ) -> Tuple[bool, Optional[List[Tuple[str, str]]]]:
        """Checks if method is reachable specifically from <clinit> in the same class or any class."""
        norm_cls = class_name.replace(".", "/")
        target = (norm_cls, method_name)
        # First check same class clinit
        same_clinit = (norm_cls, "<clinit>")
        if same_clinit in self.entry_points:
            path = self.find_path(same_clinit, target, max_depth=max_depth)
            if path:
                return True, path

        # Check all clinits
        for ep in self.entry_points:
            if ep[1] == "<clinit>":
                path = self.find_path(ep, target, max_depth=max_depth)
                if path:
                    return True, path
        return False, None

    @classmethod
    def build(cls, classes: List[ClassInfo]) -> "CallGraph":
        """Constructs call graph across all provided ClassInfo objects."""
        cg = cls()
        try:
            from javadecompiler.disassembler import disassembleMethod
        except ImportError:
            from disassembler import disassembleMethod

        for c_info in classes:
            c_name = c_info.class_name.replace(".", "/")

            for m_name, m_info in c_info.methods.items():
                caller = (c_name, m_name)

                # Mark standard entry points
                if m_name == "<clinit>":
                    cg.entry_points.add(caller)
                elif m_name == "main" and m_info.is_static:
                    cg.entry_points.add(caller)
                elif m_name in ("premain", "agentmain"):
                    cg.entry_points.add(caller)

                if not m_info.bytecode:
                    continue

                try:
                    instructions = disassembleMethod(m_name, m_info.bytecode)
                except Exception:
                    continue

                for instr in instructions:
                    call = get_call_info(c_info.constant_pool, instr)
                    if call:
                        callee_cls = call.get("class", "").replace(".", "/")
                        callee_m = call.get("name", "")
                        if callee_cls and callee_m:
                            cg.add_edge(caller, (callee_cls, callee_m))

        return cg
