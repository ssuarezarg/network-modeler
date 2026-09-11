"""Hierarchical splitting of a Cisco-style configuration, with line accounting.

The accounting is the point. Any parser can produce a plausible-looking model;
what distinguishes a trustworthy one is being able to say which input lines it
actually understood and which it ignored. Without that number there is no way to
tell "we modelled this device" from "we silently discarded half of it", and the
model looks equally convincing either way.

So every significant line is tracked, handlers mark what they consume, and
`coverage()` reports the remainder along with samples of what was skipped.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Lines that carry no configuration: blank, or a bare comment marker. They are
# excluded from the denominator so coverage is not inflated by the `!` separators
# that make up a large share of any Cisco config.
_INSIGNIFICANT = re.compile(r"^\s*(?:!.*)?$")

# `banner motd ^C` ... `^C`. The body is free text, not configuration, and it is
# not indented - so without special handling every line of it becomes a
# top-level block. That is not merely untidy: a banner containing the word
# "interface" or "ip route" would be parsed as configuration and invent
# equipment that does not exist. Banners are captured whole and never walked.
_BANNER_START = re.compile(r"^banner\s+(\S+)\s+(\S)", re.I)


@dataclass
class Block:
    """A top-level configuration line plus its indented children."""

    header: str
    children: list[str] = field(default_factory=list)
    lineno: int = 0
    line_numbers: list[int] = field(default_factory=list)

    def child_values(self, pattern: str) -> list[str]:
        """Captured group 1 of every child matching `pattern`."""
        compiled = re.compile(pattern)
        out = []
        for child in self.children:
            match = compiled.match(child.strip())
            if match:
                out.append(match.group(1))
        return out

    def first(self, pattern: str) -> str | None:
        values = self.child_values(pattern)
        return values[0] if values else None

    def has(self, pattern: str) -> bool:
        compiled = re.compile(pattern)
        return any(compiled.match(child.strip()) for child in self.children)


class ConfigDocument:
    """A configuration split into blocks, tracking which lines were understood."""

    def __init__(self, text: str):
        self.text = text
        self.lines = text.split("\n")
        self.blocks: list[Block] = []
        self._significant: set[int] = set()
        self._consumed: set[int] = set()
        self._acknowledged: set[int] = set()
        self._split()

    def _split(self) -> None:
        current: Block | None = None
        banner_delimiter: str | None = None

        for index, raw in enumerate(self.lines, start=1):
            if banner_delimiter is not None:
                # Inside a banner: every line belongs to it, whatever it says.
                self._significant.add(index)
                if current is not None:
                    current.children.append(raw)
                    current.line_numbers.append(index)
                if banner_delimiter in raw:
                    banner_delimiter = None
                continue

            if not _INSIGNIFICANT.match(raw):
                self._significant.add(index)
            else:
                # Skip, but do NOT close the current block. IOS emits indented
                # `!` separators *inside* blocks - between address-families in
                # `router bgp`, for instance. Treating those as terminators
                # orphans every line after them into bogus top-level blocks.
                # Hierarchy comes from indentation; `!` is only a separator.
                continue

            if raw[:1].isspace():
                if current is not None:
                    current.children.append(raw)
                    current.line_numbers.append(index)
                    continue
                # Indented line with no open block: treat as top level rather
                # than dropping it, so it still counts against coverage.
            current = Block(header=raw.strip(), lineno=index, line_numbers=[index])
            self.blocks.append(current)

            banner = _BANNER_START.match(current.header)
            if banner:
                delimiter = banner.group(2)
                # A single-line banner closes on the same line.
                if current.header.count(delimiter) < 2:
                    banner_delimiter = delimiter

    def find(self, pattern: str) -> list[Block]:
        compiled = re.compile(pattern)
        return [block for block in self.blocks if compiled.match(block.header)]

    def consume(self, block: Block) -> None:
        """Mark a block as having produced model content."""
        self._consumed.update(block.line_numbers)

    def consume_line(self, lineno: int) -> None:
        self._consumed.add(lineno)

    def acknowledge(self, block: Block) -> None:
        """Mark a block as recognised but deliberately not modelled.

        Kept separate from `consume` so the coverage figure cannot quietly
        inflate itself. Counting `service timestamps` as "modelled" because we
        recognise it would make the number meaningless - the question coverage
        answers is how much of the device is in the model, not how much of the
        text we can pattern-match.
        """
        self._acknowledged.update(block.line_numbers)

    @property
    def significant_lines(self) -> int:
        return len(self._significant)

    @property
    def consumed_lines(self) -> int:
        return len(self._consumed & self._significant)

    @property
    def acknowledged_lines(self) -> int:
        return len(self._acknowledged & self._significant - self._consumed)

    def coverage(self) -> float:
        """Fraction of significant lines that produced model content."""
        if not self._significant:
            return 1.0
        return self.consumed_lines / self.significant_lines

    def accounted(self) -> float:
        """Fraction either modelled or explicitly classified as not-modelled.

        The gap between this and 1.0 is what nobody has looked at yet - the only
        number that says whether the parser is finished.
        """
        if not self._significant:
            return 1.0
        seen = (self._consumed | self._acknowledged) & self._significant
        return len(seen) / self.significant_lines

    def unconsumed(self) -> list[tuple[int, str]]:
        """Lines neither modelled nor acknowledged: genuinely unrecognised."""
        missing = sorted(self._significant - self._consumed - self._acknowledged)
        return [(n, self.lines[n - 1].strip()) for n in missing]

    def unconsumed_summary(self, limit: int = 15) -> list[tuple[str, int]]:
        """Most common unmodelled command prefixes, so the next parser to write
        is obvious rather than guessed."""
        counts: dict[str, int] = {}
        for _, line in self.unconsumed():
            key = " ".join(line.split()[:2])
            counts[key] = counts.get(key, 0) + 1
        return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
