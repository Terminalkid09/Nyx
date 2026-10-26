"""Attack path graph (F-03).

Findings are only useful as a chain: an exposed key on host A, an admin
endpoint on host A, an IDOR that the key unlocks. This module builds a small
graph from stored findings with two conservative heuristics:

* findings that share a request_id are the same exchange -> an edge;
* on the same host, a lower-severity reconnaissance finding points at a
  higher-severity one ("this exposure is how you reach that weakness").

No LLM, no speculation: an edge always carries the reason that created it, so
the UI can show *why* two findings are connected.
"""
from dataclasses import asdict, dataclass, field

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# A long-lived session accumulates thousands of findings and the original
# all-pairs loop created one edge per couple: on a real database
# ``GET /api/attack-path/{session_id}`` built millions of dataclasses, and the
# backend process died of memory exhaustion while serialising them (observed
# live: the API port stopped answering with no traceback). Bound both the node
# set (highest severity first) and the edges contributed by each host.
MAX_NODES = 500
MAX_EDGES_PER_HOST = 100


@dataclass
class Node:
    id: str
    title: str
    severity: str
    host: str
    cwe: str | None = None
    request_id: str | None = None


@dataclass
class Edge:
    source: str
    target: str
    reason: str


@dataclass
class AttackGraph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "nodes": [asdict(node) for node in self.nodes],
            "edges": [asdict(edge) for edge in self.edges],
        }


def _host_from_url(url: str | None) -> str:
    if not url:
        return ""
    try:
        from urllib.parse import urlparse
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def build_graph(findings: list[dict]) -> AttackGraph:
    """Build a deterministic, bounded graph from finding dictionaries.

    Only the ``MAX_NODES`` most severe findings are kept (the operator is
    interested in the paths that matter, not in a 10k-node hairball), and each
    host contributes at most ``MAX_EDGES_PER_HOST`` links.
    """
    graph = AttackGraph()
    ranked = sorted(
        findings,
        key=lambda f: SEVERITY_RANK.get(str(f.get("severity") or "info").lower(), 0),
        reverse=True,
    )
    for index, finding in enumerate(ranked[:MAX_NODES]):
        graph.nodes.append(Node(
            id=str(finding.get("id") or index),
            title=str(finding.get("title") or "Untitled"),
            severity=str(finding.get("severity") or "info").lower(),
            host=_host_from_url(
                finding.get("url") or finding.get("host") or ""
            ) or str(finding.get("host") or "").lower(),
            cwe=finding.get("cwe"),
            request_id=(
                str(finding["request_id"]) if finding.get("request_id") else None
            ),
        ))

    seen: set[tuple[str, str, str]] = set()

    def add_edge(source: Node, target: Node, reason: str) -> None:
        if source.id == target.id:
            return
        key = (source.id, target.id, reason)
        if key in seen:
            return
        seen.add(key)
        graph.edges.append(Edge(source=source.id, target=target.id, reason=reason))

    # Same exchange: the lowest-severity finding is the exposure through which
    # the more severe ones were reached.
    by_request: dict[str, list[Node]] = {}
    for node in graph.nodes:
        if node.request_id:
            by_request.setdefault(node.request_id, []).append(node)
    linked: set[tuple[str, str]] = set()
    for group in by_request.values():
        if len(group) < 2:
            continue
        group.sort(key=lambda node: SEVERITY_RANK.get(node.severity, 0))
        low = group[0]
        for node in group[1:MAX_EDGES_PER_HOST + 1]:
            add_edge(low, node, "same_request")
            linked.add((low.id, node.id))

    # Same host: reconnaissance points at the most severe finding of that host.
    by_host: dict[str, list[Node]] = {}
    for node in graph.nodes:
        if node.host:
            by_host.setdefault(node.host, []).append(node)
    for group in by_host.values():
        if len(group) < 2:
            continue
        group.sort(key=lambda node: SEVERITY_RANK.get(node.severity, 0))
        top_rank = SEVERITY_RANK.get(group[-1].severity, 0)
        if top_rank == SEVERITY_RANK.get(group[0].severity, 0):
            continue
        high = group[-1]
        emitted = 0
        for node in group[:-1]:
            if SEVERITY_RANK.get(node.severity, 0) >= top_rank:
                continue
            if (node.id, high.id) in linked:
                continue
            add_edge(node, high, "exposure_enables_finding")
            emitted += 1
            if emitted >= MAX_EDGES_PER_HOST:
                break

    return graph
