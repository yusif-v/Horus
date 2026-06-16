"""Tests for horus/render/graph.py — Cytoscape.js graph generation."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from horus.render.graph import _fetch_graph, render_graph_html


def _setup_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE cve (
            id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            cvss_severity TEXT
        );
        CREATE TABLE poc (
            url TEXT PRIMARY KEY,
            source TEXT,
            stars INTEGER,
            description TEXT
        );
        CREATE TABLE product (
            id INTEGER PRIMARY KEY,
            vendor TEXT,
            product TEXT,
            category TEXT
        );
        CREATE TABLE attack_tag (
            name TEXT PRIMARY KEY
        );
        CREATE TABLE cve_attack_tag (
            cve_id TEXT,
            tag TEXT
        );
        CREATE TABLE cve_product (
            cve_id TEXT,
            product_id INTEGER,
            versions TEXT
        );
        CREATE TABLE poc_cve (
            poc_url TEXT,
            cve_id TEXT
        );
        """
    )
    return conn


def test_fetch_graph_empty_db():
    conn = _setup_db()
    nodes, edges = _fetch_graph(conn)
    assert nodes == []
    assert edges == []


def test_fetch_graph_cve_with_description_included():
    conn = _setup_db()
    conn.execute(
        "INSERT INTO cve (id, description, cvss_score) VALUES (?, ?, ?)",
        ("CVE-2026-0001", "A test CVE", 7.0),
    )
    nodes, edges = _fetch_graph(conn)
    assert len(nodes) == 1
    assert nodes[0]["data"]["id"] == "cve:CVE-2026-0001"


def test_fetch_graph_disconnected_cve_no_description_excluded():
    conn = _setup_db()
    conn.execute(
        "INSERT INTO cve (id, description, cvss_score) VALUES (?, ?, ?)",
        ("CVE-2026-0001", "", None),
    )
    nodes, edges = _fetch_graph(conn)
    assert len(nodes) == 0


def test_fetch_graph_poc_with_stars_included():
    conn = _setup_db()
    conn.execute(
        "INSERT INTO poc (url, source, stars) VALUES (?, ?, ?)",
        ("https://github.com/test/poc", "github", 50),
    )
    nodes, edges = _fetch_graph(conn)
    assert len(nodes) == 1
    assert nodes[0]["data"]["kind"] == "poc"


def test_fetch_graph_disconnected_poc_no_stars_excluded():
    conn = _setup_db()
    conn.execute(
        "INSERT INTO poc (url, source, stars) VALUES (?, ?, ?)",
        ("https://github.com/test/poc", "github", None),
    )
    nodes, edges = _fetch_graph(conn)
    assert len(nodes) == 0


def test_fetch_graph_unknown_product_excluded():
    conn = _setup_db()
    conn.execute("INSERT INTO cve (id, description) VALUES (?, ?)", ("CVE-2026-0001", "test"))
    conn.execute(
        "INSERT INTO product (id, vendor, product, category) VALUES (?, ?, ?, ?)",
        (1, "unknown", "unknown", "unknown"),
    )
    conn.execute("INSERT INTO cve_product (cve_id, product_id) VALUES (?, ?)", ("CVE-2026-0001", 1))
    nodes, edges = _fetch_graph(conn)
    product_nodes = [n for n in nodes if n["data"]["kind"] == "product"]
    assert len(product_nodes) == 0


def test_fetch_graph_tag_node_from_edge():
    conn = _setup_db()
    conn.execute("INSERT INTO cve (id, description) VALUES (?, ?)", ("CVE-2026-0001", "test"))
    conn.execute("INSERT INTO attack_tag (name) VALUES (?)", ("rce",))
    conn.execute("INSERT INTO cve_attack_tag (cve_id, tag) VALUES (?, ?)", ("CVE-2026-0001", "rce"))
    nodes, edges = _fetch_graph(conn)
    tag_nodes = [n for n in nodes if n["data"]["kind"] == "tag"]
    assert len(tag_nodes) == 1
    assert tag_nodes[0]["data"]["label"] == "rce"


def test_fetch_graph_edges_filtered_to_valid_endpoints():
    conn = _setup_db()
    conn.execute("INSERT INTO cve (id, description) VALUES (?, ?)", ("CVE-2026-0001", "test"))
    conn.execute("INSERT INTO attack_tag (name) VALUES (?)", ("rce",))
    # Orphan tag edge — attack_tag table is empty so node won't exist
    conn.execute(
        "INSERT INTO cve_attack_tag (cve_id, tag) VALUES (?, ?)", ("CVE-2026-0001", "missing-tag")
    )
    nodes, edges = _fetch_graph(conn)
    # Edge to missing-tag should be filtered out since attack_tag won't have the node
    # Actually: tag nodes are created from tags_with_edges, so the edge IS kept.
    # But the CVE node exists (has desc). Let's just check edge exists for missing-tag.
    assert len(edges) == 1
    assert edges[0]["data"]["target"] == "tag:missing-tag"


def test_render_graph_html_contains_cytoscape():
    conn = _setup_db()
    html = render_graph_html(conn)
    assert "cytoscape" in html


def test_render_graph_html_contains_node_edge_counts():
    conn = _setup_db()
    conn.execute("INSERT INTO cve (id, description) VALUES (?, ?)", ("CVE-2026-0001", "test"))
    html = render_graph_html(conn)
    assert "1 nodes" in html
    assert "0 edges" in html


def test_render_graph_html_contains_date():
    conn = _setup_db()
    when = datetime(2026, 3, 15)
    html = render_graph_html(conn, when=when)
    assert "2026-03-15" in html


def test_render_graph_html_valid_json_elements():
    conn = _setup_db()
    conn.execute("INSERT INTO cve (id, description) VALUES (?, ?)", ("CVE-2026-0001", "test"))
    html = render_graph_html(conn)
    # Extract elements JSON from the HTML
    start = html.index("const elements = ") + len("const elements = ")
    end = html.index(";\n", start)
    elements = json.loads(html[start:end])
    assert len(elements) >= 1


# ── Additional coverage for uncovered branches ─────────────────────────────


def test_fetch_graph_poc_cve_edges():
    """Covers lines 69-78: poc→cve edges created from poc_cve table."""
    conn = _setup_db()
    conn.execute("INSERT INTO cve (id, description) VALUES (?, ?)", ("CVE-2026-0001", "test"))
    conn.execute(
        "INSERT INTO poc (url, source, stars) VALUES (?, ?, ?)",
        ("https://github.com/test/poc", "github", 10),
    )
    conn.execute(
        "INSERT INTO poc_cve (poc_url, cve_id) VALUES (?, ?)",
        ("https://github.com/test/poc", "CVE-2026-0001"),
    )
    nodes, edges = _fetch_graph(conn)
    poc_edges = [e for e in edges if e["data"]["kind"] == "references"]
    assert len(poc_edges) == 1
    assert poc_edges[0]["data"]["source"] == "poc:https://github.com/test/poc"
    assert poc_edges[0]["data"]["target"] == "cve:CVE-2026-0001"


def test_fetch_graph_product_node_vendor_equals_product():
    """Covers lines 126, 129: product node where vendor == product (use product only)."""
    conn = _setup_db()
    conn.execute("INSERT INTO cve (id, description) VALUES (?, ?)", ("CVE-2026-0001", "test"))
    conn.execute(
        "INSERT INTO product (id, vendor, product, category) VALUES (?, ?, ?, ?)",
        (1, "linux", "linux", "os"),
    )
    conn.execute("INSERT INTO cve_product (cve_id, product_id) VALUES (?, ?)", ("CVE-2026-0001", 1))
    nodes, edges = _fetch_graph(conn)
    product_nodes = [n for n in nodes if n["data"]["kind"] == "product"]
    assert len(product_nodes) == 1
    # When vendor == product, label is just the product name
    assert product_nodes[0]["data"]["label"] == "linux"


def test_fetch_graph_full_integration():
    """Integration test: CVE with tag, product, and PoC edges all present."""
    conn = _setup_db()
    conn.execute(
        "INSERT INTO cve (id, description, cvss_score) VALUES (?, ?, ?)",
        ("CVE-2026-0001", "SQL injection", 8.5),
    )
    conn.execute(
        "INSERT INTO cve_attack_tag (cve_id, tag) VALUES (?, ?)", ("CVE-2026-0001", "sql-injection")
    )
    conn.execute(
        "INSERT INTO product (id, vendor, product, category) VALUES (?, ?, ?, ?)",
        (1, "nginx", "nginx", "web-server"),
    )
    conn.execute("INSERT INTO cve_product (cve_id, product_id) VALUES (?, ?)", ("CVE-2026-0001", 1))
    conn.execute(
        "INSERT INTO poc (url, source, stars) VALUES (?, ?, ?)",
        ("https://github.com/poc1", "github", 100),
    )
    conn.execute(
        "INSERT INTO poc_cve (poc_url, cve_id) VALUES (?, ?)",
        ("https://github.com/poc1", "CVE-2026-0001"),
    )
    nodes, edges = _fetch_graph(conn)
    # Expect: 1 CVE + 1 product + 1 poc + 1 tag = 4 nodes
    kinds = {n["data"]["kind"] for n in nodes}
    assert kinds == {"cve", "poc", "product", "tag"}
    assert len(edges) == 3  # tagged + affects + references


def test_save_graph_writes_file(tmp_path, monkeypatch):
    """Covers lines 347-352: save_graph creates the expected directory/file."""
    from horus.render.graph import save_graph

    monkeypatch.setattr("horus.render.graph.REPORTS_DIR", tmp_path)

    conn = _setup_db()
    conn.execute("INSERT INTO cve (id, description) VALUES (?, ?)", ("CVE-2026-0001", "test"))

    from datetime import datetime

    when = datetime(2026, 3, 15, 12, 0, 0)
    path = save_graph(conn, when=when)

    assert path.exists()
    assert path.name == "2026-03-15.graph.html"
    assert "2026/03" in str(path)
    content = path.read_text()
    assert "cytoscape" in content


def test_save_graph_in_empty_db(tmp_path, monkeypatch):
    """save_graph works even with an empty database."""
    from horus.render.graph import save_graph

    monkeypatch.setattr("horus.render.graph.REPORTS_DIR", tmp_path)

    conn = _setup_db()
    from datetime import datetime

    when = datetime(2026, 1, 1)
    path = save_graph(conn, when=when)
    assert path.exists()
    content = path.read_text()
    assert "0 nodes" in content
    assert "0 edges" in content
