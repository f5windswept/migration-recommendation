"""Small parsers for captured HTML, tmsh configuration, and iHealth graph JSON."""
from dataclasses import dataclass
from html.parser import HTMLParser
import math
import re
import statistics


def clean(value):
    return re.sub(r"\s+", " ", value).strip()


class Document(HTMLParser):
    def __init__(self, raw):
        super().__init__(convert_charrefs=True)
        self.parts, self.links, self.tables, self.definitions = [], [], [], []
        self.header_fields, self._header, self._cell_class = {}, None, ""
        self.pres, self._pre, self._table, self._row, self._cell = [], None, None, None, None
        self._definition, self._term, self._skip = None, None, 0
        self.feed(raw)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        if tag in ("div", "p", "li", "tr", "dt", "dd", "h1", "h2", "h3", "h4", "br", "pre"):
            self.parts.append("\n")
        if tag in ("td", "th"):
            self.parts.append(" | ")
            self._cell = []
            self._cell_class = attrs.get("class", "")
        if tag == "table":
            self._table = []
        if tag == "tr":
            self._row = []
        if tag == "pre":
            self._pre = []
        if tag in ("dt", "dd"):
            self._definition = []
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "input" and attrs.get("type") == "checkbox" and self._cell is not None:
            self._cell.append("true" if "checked" in attrs else "false")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        if tag == "pre" and self._pre is not None:
            self.pres.append("".join(self._pre))
            self._pre = None
        if tag in ("td", "th") and self._cell is not None:
            value = clean("".join(self._cell))
            if "header" in self._cell_class.split():
                self._header = value
            elif "value" in self._cell_class.split() and self._header:
                self.header_fields[self._header] = value
                self._header = None
            if self._row is not None:
                self._row.append(value)
            self._cell = None
        if tag == "tr" and self._row is not None:
            if self._table is not None:
                self._table.append(self._row)
            self._row = None
        if tag == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None
        if tag in ("dt", "dd") and self._definition is not None:
            value = clean("".join(self._definition))
            if tag == "dt":
                self._term = value
            elif self._term:
                self.definitions.append((self._term, value))
            self._definition = None

    def handle_data(self, data):
        if self._skip:
            return
        self.parts.append(data)
        for target in (self._pre, self._cell, self._definition):
            if target is not None:
                target.append(data)

    @property
    def text(self):
        return "\n".join(line for line in (clean(x) for x in "".join(self.parts).splitlines()) if line)

    @property
    def command(self):
        return "\n".join(self.pres) if self.pres else self.text


def has_capture(text):
    return bool(text and text.strip()) and "No data found in QKView" not in text and "[No data available]" != text.strip()


@dataclass
class Node:
    head: tuple
    children: object = None

    def child(self, key):
        return next((node for node in self.children or [] if node.head and node.head[0] == key), None)

    def value(self, key, default=None):
        node = self.child(key)
        return " ".join(node.head[1:]) if node and len(node.head) > 1 else default

    def words(self, key):
        node = self.child(key)
        if not node:
            return []
        return list(node.head[1:]) if node.children is None else [word for child in node.children for word in child.head]


def lex_tmsh(text):
    i = 0
    while i < len(text):
        char = text[i]
        if char in " \t\r":
            i += 1
        elif char in "\n;{}":
            yield "\n" if char == ";" else char
            i += 1
        elif char == "#":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        else:
            quote = char == '"'
            if quote:
                i += 1
            word = []
            while i < len(text):
                char = text[i]
                if char == "\\" and i + 1 < len(text):
                    word.append(text[i + 1])
                    i += 2
                elif quote and char == '"':
                    i += 1
                    break
                elif not quote and (char.isspace() or char in "{};"):
                    break
                else:
                    word.append(char)
                    i += 1
            else:
                if quote:
                    raise ValueError("Unclosed quoted configuration value")
            # Keep quoted braces distinct from structural tokens.
            yield ("word", "".join(word))


def parse_tmsh(text):
    tokens = iter(lex_tmsh(text))

    def block(nested=False):
        nodes, head = [], []
        for token in tokens:
            if isinstance(token, tuple):
                head.append(token[1])
            elif token == "{":
                if not head:
                    raise ValueError("Configuration block missing a name")
                nodes.append(Node(tuple(head), block(True)))
                head = []
            elif token in ("\n", "}"):
                if head:
                    nodes.append(Node(tuple(head)))
                    head = []
                if token == "}":
                    if not nested:
                        raise ValueError("Unexpected closing configuration brace")
                    return nodes
        if nested:
            raise ValueError("Incomplete configuration block")
        if head:
            nodes.append(Node(tuple(head)))
        return nodes

    return block()


def config_objects(text, prefix):
    if not has_capture(text):
        return None
    return {node.head[-1]: node for node in parse_tmsh(text)
            if node.children is not None and tuple(node.head[:-1]) == tuple(prefix.split())}


def irules(text):
    if not has_capture(text):
        return None
    # Tcl bodies remain opaque; do not interpret/execute customer code.
    matches = list(re.finditer(r"(?m)^ltm rule (\S+)\s*\{", text))
    return {match[1]: text[match.end():matches[i + 1].start() if i + 1 < len(matches) else len(text)]
            for i, match in enumerate(matches)}


def command_map(data):
    result = {}

    def walk(node):
        if isinstance(node, dict):
            value = node.get("data", {})
            if isinstance(value, dict) and isinstance(value.get("attr"), dict):
                title, href = value.get("title"), value["attr"].get("href")
                if title and href:
                    result[title] = href
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(data)
    return result


def numeric(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def series_stats(rows, key):
    valid = [(row.get(key), row.get("time")) for row in rows if numeric(row.get(key)) and row[key] >= 0]
    values = sorted(value for value, _ in valid)
    if not values:
        return {"valid": 0, "missing_or_invalid": len(rows), "max": None, "p95": None, "mean": None}
    return {"valid": len(values), "missing_or_invalid": len(rows) - len(values),
            "mean": statistics.fmean(values), "p95": values[math.ceil(.95 * len(values)) - 1],
            "max": values[-1], "max_time": next(time for value, time in valid if value == values[-1]),
            "last": rows[-1].get(key) if rows and numeric(rows[-1].get(key)) and rows[-1][key] >= 0 else None}


def graph_data(raw):
    if raw.get("success") is False or not isinstance(raw.get("data"), dict):
        raise ValueError("iHealth did not return graph data")
    data = raw["data"]
    if not isinstance(data.get("data"), list) or not isinstance(data.get("criteria"), dict):
        raise ValueError("Unexpected graph schema")
    rows, criteria = data["data"], data["criteria"]
    if any(not isinstance(row, dict) or "time" not in row for row in rows):
        raise ValueError("Invalid graph rows")
    if len({row["time"] for row in rows}) != len(rows):
        raise ValueError("Duplicate graph timestamps")
    return rows, criteria


def summarize_graph(raw):
    rows, criteria = graph_data(raw)
    result = {"title": criteria.get("title"), "units": criteria.get("ylabel"), "samples": len(rows),
              "start": rows[0]["time"] if rows else None, "end": rows[-1]["time"] if rows else None,
              "timezone": "iHealth graph labels; timezone not inferred", "series": {}}
    keys = {key for row in rows for key in row if re.fullmatch(r"val\d+", key)}
    for key in sorted(keys):
        index = key[3:]
        result["series"][key] = dict(series_stats(rows, key), label=criteria.get("ll" + index, key),
                                    interval_seconds=criteria.get("i" + index), expression=criteria.get("e" + index))
    return result


def aligned_outbound(client, server):
    left, lc = graph_data(client)
    right, rc = graph_data(server)
    def field(criteria, label):
        return next(("val" + k[2:] for k, value in criteria.items() if k.startswith("ll") and value == label), None)
    lk, rk = field(lc, "Client Bits Out"), field(rc, "Server Bits Out")
    if not lk or not rk or lc.get("ylabel") != "Bits/sec" or rc.get("ylabel") != "Bits/sec":
        raise ValueError("Cannot identify outbound graph fields/units")
    if lc.get("i" + lk[3:]) != rc.get("i" + rk[3:]):
        raise ValueError("Outbound series have different aggregation intervals")
    by_time = {row["time"]: row.get(rk) for row in right}
    rows = [{"time": row["time"], "val0": row[lk] + by_time[row["time"]]}
            for row in left if numeric(row.get(lk)) and row[lk] >= 0
            and numeric(by_time.get(row["time"])) and by_time[row["time"]] >= 0]
    return dict(series_stats(rows, "val0"), units="Bits/sec", aligned_samples=len(rows),
                unmatched_or_invalid=len(left) - len(rows), interval_seconds=lc.get("i" + lk[3:]),
                interpretation="Screening metric only; not a verified VE license enforcement counter")
