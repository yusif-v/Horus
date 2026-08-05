# AI Weekly Report Analyzer — Design Spec

*Created 2026-08-05, for Horus v0.14*

## Purpose

Add AI-powered analysis to the weekly threat intelligence report. The AI writes narrative sections (executive summary, trend analysis, risk assessment, recommendations) and performs QA bug detection (data anomalies + report correctness). This addresses the original motivation: catching technical bugs in the pipeline output that pure template rendering cannot detect.

## Architecture

### Package structure

```
horus/ai/
├── __init__.py           # Public API: analyze_weekly_report()
├── base.py               # AbstractAIProvider + AIAnalysisResult dataclass
├── openai_provider.py    # OpenAI implementation
├── anthropic_provider.py # Anthropic implementation
├── ollama_provider.py    # Ollama (local) implementation
├── prompts.py            # Prompt templates
└── selector.py           # Provider selection from config/env
```

### Data flow

```
gather_weekly_data() → WeeklyData
        ↓
render_weekly_report(data, fmt="md") → template_report_text
        ↓
analyze_weekly_report(data, template_report_text, provider) → AIAnalysisResult
        ↓
merge into final report (AI narrative + template tables + QA section)
```

The analyzer is a **pure function**: `WeeklyData + rendered_report_text → AIAnalysisResult`. No side effects, no DB access, no pipeline mutation.

### Provider abstraction

```python
@dataclass
class AIAnalysisResult:
    narrative: str              # Full narrative report sections
    qa_issues: list[str]        # Data anomalies and report bugs found
    metadata: dict[str, Any]    # Provider, model, tokens, latency

class AbstractAIProvider(Protocol):
    def analyze(self, data_prompt: str, qa_prompt: str) -> AIAnalysisResult: ...
```

Each provider implements `analyze()` — serializes the WeeklyData to a structured prompt, sends to the LLM, parses the JSON response into `AIAnalysisResult`.

## Two-Pass Analysis (Single API Call)

Both passes happen in **one API call** with a structured JSON response to minimize cost/latency:

### Pass 1 — Narrative Generation
- **Input**: top-15 CVEs (ordered by reputation_score DESC, then cvss_score DESC), summary stats, top vendors/tags, top news
- **Output sections**:
  - Executive Summary (2-3 paragraphs)
  - Trend Analysis (week-over-week changes, emerging patterns)
  - Risk Assessment (critical threats requiring immediate attention)
  - Recommended Actions (prioritized by severity/exploitability)

### Pass 2 — QA Bug Detection
- **Input**: wider data sample (top-50 CVEs ordered same as above, severity breakdown, WoW deltas, the rendered template report text)
- **Output**: List of issues found:
  - **Data anomalies**: CVSS/EPSS mismatches (e.g. CVSS 9.5 but EPSS 0.001), KEV entries without due dates, severity outliers, sudden count spikes/drops
  - **Report correctness**: Number mismatches between sections, contradictions in trend descriptions, formatting errors

### Prompt format

The system prompt instructs the LLM to act as a cybersecurity analyst and respond with valid JSON only. The user message contains both the structured weekly data and the rendered template report. The LLM returns a single JSON object:

```json
{
  "narrative": {
    "executive_summary": "...",
    "trend_analysis": "...",
    "risk_assessment": "...",
    "recommended_actions": "..."
  },
  "qa_issues": [
    "CVE-2026-X has CVSS 9.8 but EPSS 0.001 — possible scoring error",
    "KEV entry CVE-2026-Y missing due_date",
    "Executive summary says '150 CVEs' but table shows 147"
  ]
}
```

### Format handling

The AI augmentation works with all three output formats (text, md, html):
- **text/md**: AI sections inserted as plain text/markdown prose
- **html**: AI sections rendered as styled HTML `<section>` blocks within the existing dark-themed template
- The AI generates prose only (no markdown formatting in narrative text) — the renderer wraps it appropriately for each format

## Integration with Weekly Report

### CLI flags

```
--weekly-report          Generate weekly report (existing)
--ai                     Augment with AI analysis (new)
--ai-provider {openai,anthropic,ollama}  Override provider (new)
--ai-model MODEL         Override model (new)
```

### Output structure (when --ai is set)

```
┌─────────────────────────────────────────┐
│  AI NARRATIVE SECTION                   │
│  Executive Summary                      │
│  Trend Analysis                         │
│  Risk Assessment                        │
│  Recommended Actions                    │
├─────────────────────────────────────────┤
│  TEMPLATE DATA TABLES (existing)        │
│  Top CVEs | Vendors | Tags | etc.       │
├─────────────────────────────────────────┤
│  AI QUALITY ASSURANCE SECTION           │
│  Data anomalies found: N                │
│  Report issues found: M                 │
│  [list of issues]                       │
└─────────────────────────────────────────┘
```

### Fallback behavior

When `--ai` is set but AI is unavailable (no API key, timeout, error):
1. Emit warning to stderr
2. Render template report as normal
3. Append note: "AI analysis unavailable — [reason]"

The report always works, with or without AI.

## Configuration

### Environment variables (simplest)

```bash
export HORUS_AI_PROVIDER=openai
export OPENAI_API_KEY=sk-...

# OR
export HORUS_AI_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# OR
export HORUS_AI_PROVIDER=ollama
# No key needed, ensure Ollama is running
```

### horus.yaml (server mode)

```yaml
ai:
  provider: openai
  model: gpt-4o
  api_key: ${OPENAI_API_KEY}
  ollama_url: http://localhost:11434
  timeout_seconds: 120
  max_retries: 2
```

### Provider defaults

| Provider | Default Model | Context Window |
|----------|--------------|----------------|
| OpenAI | gpt-4o | 128K |
| Anthropic | claude-sonnet-4-20250514 | 200K |
| Ollama | llama3:70b | 8K-128K |

## Error Handling

| Scenario | Behavior |
|----------|----------|
| No API key configured | Skip AI, stderr warning, template-only |
| API timeout (default 120s) | Retry up to 2x, then fallback |
| Malformed AI response (invalid JSON) | Log error, fallback to template |
| Partial AI response (narrative only) | Use what we have, skip QA section |
| Ollama not running | Skip AI, stderr warning |
| Rate limited (429) | Exponential backoff, then fallback |

## Testing Strategy

### Unit tests (`tests/ai/`)

1. **Provider mocking**: Mock `AbstractAIProvider` to test integration without API calls
2. **Prompt tests**: Verify prompts contain all required data fields
3. **Fallback tests**: Verify graceful degradation on every failure mode
4. **Serialization tests**: Verify WeeklyData → prompt text is complete
5. **Selector tests**: Verify provider selection from env vars
6. **Result parsing tests**: Verify JSON → AIAnalysisResult parsing, including malformed responses

### No integration tests with real APIs

Avoid cost and flakiness. Providers get interface compliance tests only.

## Dependencies

- `openai` package (optional, only if using OpenAI)
- `anthropic` package (optional, only if using Anthropic)
- `requests` (already a dependency, for Ollama)

All AI dependencies are **optional extras** in pyproject.toml:
```toml
[project.optional-dependencies]
ai = ["openai>=1.0", "anthropic>=0.30"]
```

## Security

- API keys read from env vars only — never logged or stored in DB
- Prompt content is data-only (no system prompt injection vectors)
- No user-generated content sent to AI (only structured CVE data)
- Ollama provider for air-gapped deployments

## Token Budget

Estimated per-report token usage:

| Component | Tokens |
|-----------|--------|
| System prompt | ~500 |
| WeeklyData serialization (Pass 1: stats + top-15 CVEs + vendors + tags + news) | ~3,000 |
| Extended data (Pass 2: top-50 CVEs + rendered report) | ~5,000 |
| Response (narrative + QA issues) | ~1,500 |
| **Total** | **~10,000** |

Fits comfortably within all provider context windows. For cost control, WeeklyData is serialized to compact JSON (no verbose descriptions beyond 100 chars, no null fields).

## Implementation Order

1. `base.py` — interfaces and dataclasses
2. `prompts.py` — prompt templates
3. `ollama_provider.py` — simplest provider first (no SDK dependency)
4. `openai_provider.py` — most common provider
5. `anthropic_provider.py` — alternative provider
6. `selector.py` — provider selection logic
7. `__init__.py` — public API function
8. CLI integration — `--ai` flag wiring
9. Tests for all of the above
