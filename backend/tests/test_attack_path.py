"""F-03: correlation heuristics for the attack path graph."""
from modules.attack_path.graph import MAX_EDGES_PER_HOST, MAX_NODES, build_graph


def test_same_request_creates_an_edge():
    findings = [
        {"id": "a", "title": "Leaked key", "severity": "medium",
         "url": "https://app.example/", "request_id": "r1"},
        {"id": "b", "title": "Admin panel", "severity": "high",
         "url": "https://app.example/admin", "request_id": "r1"},
    ]
    graph = build_graph(findings)
    assert len(graph.nodes) == 2
    assert graph.edges[0].reason == "same_request"
    assert graph.edges[0].source == "a"
    assert graph.edges[0].target == "b"


def test_same_host_low_to_high_edge():
    findings = [
        {"id": "a", "title": "Verbose error", "severity": "low",
         "url": "https://app.example/x"},
        {"id": "b", "title": "SQLi", "severity": "critical",
         "url": "https://app.example/y"},
    ]
    graph = build_graph(findings)
    assert len(graph.edges) == 1
    assert graph.edges[0].reason == "exposure_enables_finding"
    assert graph.edges[0].source == "a"
    assert graph.edges[0].target == "b"


def test_different_hosts_are_not_linked():
    findings = [
        {"id": "a", "title": "Low", "severity": "low", "url": "https://a.example/"},
        {"id": "b", "title": "High", "severity": "high", "url": "https://b.example/"},
    ]
    assert build_graph(findings).edges == []


def test_same_severity_is_not_linked():
    findings = [
        {"id": "a", "title": "A", "severity": "high", "url": "https://a.example/1"},
        {"id": "b", "title": "B", "severity": "high", "url": "https://a.example/2"},
    ]
    assert build_graph(findings).edges == []


def test_empty_findings():
    graph = build_graph([])
    assert graph.to_dict() == {"nodes": [], "edges": []}


def test_long_lived_session_stays_bounded():
    """10k findings must not build a quadratic graph (that killed the backend)."""
    findings = [
        {
            "id": f"f{i}",
            "title": f"Finding {i}",
            "severity": ["low", "medium", "high", "critical"][i % 4],
            "url": f"https://h{i % 20}.example/x",
        }
        for i in range(10_000)
    ]

    graph = build_graph(findings)

    assert len(graph.nodes) == MAX_NODES
    assert len(graph.edges) <= MAX_EDGES_PER_HOST * 20


def test_same_request_edge_is_not_duplicated_by_host_heuristic():
    findings = [
        {"id": "a", "title": "Leaked key", "severity": "medium",
         "url": "https://app.example/", "request_id": "r1"},
        {"id": "b", "title": "Admin panel", "severity": "high",
         "url": "https://app.example/admin", "request_id": "r1"},
    ]
    graph = build_graph(findings)
    assert [(edge.source, edge.target, edge.reason) for edge in graph.edges] == [
        ("a", "b", "same_request")
    ]
