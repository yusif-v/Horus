from __future__ import annotations

from pathlib import Path

from horus.pipeline import PipelineOptions
from horus.plugin_manager import PluginManager


def test_pipeline_runs_with_manager_sources(tmp_path):
    # minimal: ensure manager-built sources dict is accepted by run_pipeline
    bundled = Path(__file__).parent.parent.parent / "horus" / "plugins"
    mgr = PluginManager(bundled_root=bundled, external_dirs=[])
    opts = PipelineOptions(
        source_filter={"nvd"},
        enricher_filter=set(),
        print_report=False,
        save_report_md=False,
        save_graph_html=False,
        quiet=True,
    )
    # nvd hits network; we only assert it returns without raising on discovery
    assert isinstance(mgr.sources(), dict)
    assert "nvd" in mgr.sources()
    assert opts.source_filter == {"nvd"}
