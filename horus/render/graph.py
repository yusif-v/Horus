"""Generate a self-contained Cytoscape.js HTML graph from the DB.

Nodes: CVE, PoC, Product, AttackTag.
Edges: cve→product (affects), cve→tag (tagged), poc→cve (references).

Floating nodes (no edges and no real description) are filtered out so the
graph stays readable.
"""


from __future__ import annotations
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from ..config import REPORTS_DIR


# ---------------------------------------------------------------------------
# Data extraction
# ---------------------------------------------------------------------------

def _fetch_graph(conn: sqlite3.Connection) -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    edges: list[dict] = []

    cves_with_edges: set[str] = set()
    products_with_edges: set[int] = set()
    tags_with_edges: set[str] = set()

    # Edges first, so we know which nodes are connected
    for cve_id, tag in conn.execute(
        'SELECT cve_id, tag FROM cve_attack_tag',
    ):
        edges.append({'data': {
            'source': f'cve:{cve_id}', 'target': f'tag:{tag}', 'kind': 'tagged',
        }})
        cves_with_edges.add(cve_id)
        tags_with_edges.add(tag)

    for cve_id, product_id in conn.execute(
        'SELECT cve_id, product_id FROM cve_product',
    ):
        edges.append({'data': {
            'source': f'cve:{cve_id}', 'target': f'product:{product_id}',
            'kind': 'affects',
        }})
        cves_with_edges.add(cve_id)
        products_with_edges.add(product_id)

    for poc_url, cve_id in conn.execute(
        'SELECT poc_url, cve_id FROM poc_cve',
    ):
        edges.append({'data': {
            'source': f'poc:{poc_url}', 'target': f'cve:{cve_id}',
            'kind': 'references',
        }})
        cves_with_edges.add(cve_id)

    pocs_with_edges = {
        row[0] for row in conn.execute('SELECT DISTINCT poc_url FROM poc_cve')
    }

    # CVE nodes: keep if connected or if it has real description
    for cve_id, desc, score, severity in conn.execute(
        'SELECT id, description, cvss_score, cvss_severity FROM cve',
    ):
        if cve_id not in cves_with_edges and not desc:
            continue
        nodes.append({'data': {
            'id': f'cve:{cve_id}',
            'label': cve_id,
            'kind': 'cve',
            'cvss': score or 0,
            'severity': severity or '',
            'description': (desc or '')[:240],
        }})

    # PoC nodes: keep if connected or if it has stars
    for url, stars, description in conn.execute(
        'SELECT url, stars, description FROM poc',
    ):
        if url not in pocs_with_edges and not stars:
            continue
        label = url.rsplit('/', 1)[-1] if '/' in url else url
        nodes.append({'data': {
            'id': f'poc:{url}',
            'label': label,
            'kind': 'poc',
            'url': url,
            'stars': stars or 0,
            'description': (description or '')[:240],
        }})

    # Product nodes: only connected, skip the unknown placeholder
    for pid, vendor, product, category in conn.execute(
        'SELECT id, vendor, product, category FROM product',
    ):
        if pid not in products_with_edges:
            continue
        if vendor == 'unknown' and product == 'unknown':
            continue
        nodes.append({'data': {
            'id': f'product:{pid}',
            'label': f'{vendor}/{product}' if vendor != product else product,
            'kind': 'product',
            'category': category,
        }})

    # Attack tag nodes
    for tag in tags_with_edges:
        nodes.append({'data': {
            'id': f'tag:{tag}', 'label': tag, 'kind': 'tag',
        }})

    # Drop edges whose endpoints got filtered out
    valid_ids = {n['data']['id'] for n in nodes}
    edges = [
        e for e in edges
        if e['data']['source'] in valid_ids and e['data']['target'] in valid_ids
    ]

    return nodes, edges


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

# All untrusted strings (CVE descriptions, repo descriptions, URLs) are
# inserted into the DOM via textContent / setAttribute — never innerHTML.

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Horus Graph — {date}</title>
<script src="https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"></script>
<style>
  html, body {{ margin: 0; padding: 0; height: 100%; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f1115; color: #d8d8d8; }}
  header {{ padding: 12px 18px; border-bottom: 1px solid #2a2d35; display: flex; align-items: baseline; gap: 16px; }}
  header h1 {{ margin: 0; font-size: 16px; font-weight: 600; }}
  header .stats {{ font-size: 13px; color: #9aa0a6; }}
  header .legend {{ margin-left: auto; font-size: 12px; }}
  header .legend span {{ display: inline-block; margin-right: 12px; padding-left: 14px; position: relative; }}
  header .legend span::before {{ content: ''; display: inline-block; width: 10px; height: 10px; border-radius: 50%; position: absolute; left: 0; top: 3px; }}
  header .legend .cve::before     {{ background: #e25555; }}
  header .legend .poc::before     {{ background: #4caf50; }}
  header .legend .product::before {{ background: #4f8cff; }}
  header .legend .tag::before     {{ background: #f0a93b; }}
  #cy {{ width: 100%; height: calc(100% - 51px); }}
  #panel {{ position: absolute; right: 14px; top: 64px; width: 320px; max-height: 70vh; overflow: auto; background: rgba(20, 22, 28, 0.94); border: 1px solid #2a2d35; border-radius: 8px; padding: 14px; font-size: 13px; line-height: 1.45; display: none; }}
  #panel h2 {{ margin: 0 0 6px; font-size: 14px; word-break: break-all; }}
  #panel .kind {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #9aa0a6; margin-bottom: 8px; }}
  #panel a {{ color: #6aa8ff; text-decoration: none; }}
  #panel a:hover {{ text-decoration: underline; }}
  #panel .desc {{ color: #bdbdbd; margin-top: 6px; }}
  #panel .row {{ margin-top: 2px; }}
</style>
</head>
<body>
<header>
  <h1>Horus Graph — {date}</h1>
  <div class="stats">{node_count} nodes · {edge_count} edges</div>
  <div class="legend">
    <span class="cve">CVE</span>
    <span class="poc">PoC</span>
    <span class="product">Product</span>
    <span class="tag">Tag</span>
  </div>
</header>
<div id="cy"></div>
<div id="panel"></div>
<script>
const elements = {elements_json};

const cy = cytoscape({{
  container: document.getElementById('cy'),
  elements: elements,
  style: [
    {{ selector: 'node', style: {{
      'label': 'data(label)',
      'color': '#d8d8d8',
      'font-size': '10px',
      'text-valign': 'bottom',
      'text-margin-y': 4,
      'text-outline-color': '#0f1115',
      'text-outline-width': 2,
      'border-width': 1,
      'border-color': '#0f1115',
    }} }},
    {{ selector: 'node[kind = "cve"]', style: {{
      'background-color': '#e25555',
      'width':  'mapData(cvss, 0, 10, 14, 38)',
      'height': 'mapData(cvss, 0, 10, 14, 38)',
    }} }},
    {{ selector: 'node[kind = "poc"]', style: {{
      'background-color': '#4caf50',
      'shape': 'diamond',
      'width':  'mapData(stars, 0, 200, 14, 32)',
      'height': 'mapData(stars, 0, 200, 14, 32)',
    }} }},
    {{ selector: 'node[kind = "product"]', style: {{
      'background-color': '#4f8cff',
      'shape': 'round-rectangle',
      'width': 30, 'height': 18,
    }} }},
    {{ selector: 'node[kind = "tag"]', style: {{
      'background-color': '#f0a93b',
      'shape': 'hexagon',
      'width': 22, 'height': 22,
    }} }},
    {{ selector: 'edge', style: {{
      'width': 1,
      'line-color': '#3a3f48',
      'curve-style': 'bezier',
      'target-arrow-shape': 'triangle',
      'target-arrow-color': '#3a3f48',
      'arrow-scale': 0.8,
    }} }},
    {{ selector: '.highlighted', style: {{ 'line-color': '#e25555', 'target-arrow-color': '#e25555', 'width': 2 }} }},
    {{ selector: 'node.highlighted', style: {{ 'border-color': '#fff', 'border-width': 2 }} }},
    {{ selector: '.dimmed', style: {{ 'opacity': 0.18 }} }},
  ],
  layout: {{
    name: 'cose',
    idealEdgeLength: 90,
    nodeRepulsion: 8000,
    edgeElasticity: 100,
    gravity: 0.15,
    numIter: 1500,
    animate: false,
  }},
}});

const panel = document.getElementById('panel');

function el(tag, opts) {{
  const e = document.createElement(tag);
  if (opts && opts.text)  e.textContent = opts.text;
  if (opts && opts.cls)   e.className = opts.cls;
  if (opts && opts.href)  e.setAttribute('href', opts.href);
  if (opts && opts.target) e.setAttribute('target', opts.target);
  if (opts && opts.rel)   e.setAttribute('rel', opts.rel);
  return e;
}}

function renderPanel(node) {{
  const d = node.data();
  panel.textContent = '';
  panel.appendChild(el('div', {{ cls: 'kind', text: d.kind }}));
  panel.appendChild(el('h2', {{ text: d.label }}));

  if (d.kind === 'cve') {{
    if (d.cvss) {{
      const row = el('div', {{ cls: 'row' }});
      row.appendChild(document.createTextNode('CVSS '));
      const b = el('b', {{ text: String(d.cvss) }});
      row.appendChild(b);
      if (d.severity) row.appendChild(document.createTextNode(' ' + d.severity));
      panel.appendChild(row);
    }}
    if (d.description) panel.appendChild(el('div', {{ cls: 'desc', text: d.description }}));
  }} else if (d.kind === 'poc') {{
    const row = el('div', {{ cls: 'row' }});
    const a = el('a', {{ text: d.url, href: d.url, target: '_blank', rel: 'noopener noreferrer' }});
    row.appendChild(a);
    panel.appendChild(row);
    panel.appendChild(el('div', {{ cls: 'row', text: '★ ' + d.stars }}));
    if (d.description) panel.appendChild(el('div', {{ cls: 'desc', text: d.description }}));
  }} else if (d.kind === 'product') {{
    panel.appendChild(el('div', {{ cls: 'row', text: 'category: ' + d.category }}));
  }}

  panel.style.display = 'block';
}}

cy.on('tap', 'node', (evt) => {{
  const node = evt.target;
  cy.elements().addClass('dimmed').removeClass('highlighted');
  const neighborhood = node.closedNeighborhood();
  neighborhood.removeClass('dimmed').addClass('highlighted');
  renderPanel(node);
}});

cy.on('tap', (evt) => {{
  if (evt.target === cy) {{
    cy.elements().removeClass('dimmed').removeClass('highlighted');
    panel.style.display = 'none';
  }}
}});
</script>
</body>
</html>
"""


def render_graph_html(conn: sqlite3.Connection, when: datetime | None = None) -> str:
    nodes, edges = _fetch_graph(conn)
    elements = nodes + edges
    now = when or datetime.now()
    return _HTML_TEMPLATE.format(
        date=now.strftime('%Y-%m-%d'),
        node_count=len(nodes),
        edge_count=len(edges),
        elements_json=json.dumps(elements, separators=(',', ':')),
    )


def save_graph(conn: sqlite3.Connection, when: datetime | None = None) -> Path:
    """Write reports/YYYY/MM/YYYY-MM-DD.graph.html."""
    now = when or datetime.now()
    folder = REPORTS_DIR / f'{now.year:04d}' / f'{now.month:02d}'
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f'{now.strftime("%Y-%m-%d")}.graph.html'
    path.write_text(render_graph_html(conn, now))
    return path
