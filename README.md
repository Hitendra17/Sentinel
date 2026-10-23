# Sentinel

Sentinel is a local-first, bounded security research scanner for systems the operator owns or is explicitly authorized to assess. It collects a small amount of HTTP evidence and runs passive checks. It is an educational MVP, not a penetration-testing replacement, and does not prove a system is secure.

## What it does

The CLI accepts a URL directly, creates an exact temporary scope when `--scope` is omitted, and requires explicit authorization for non-loopback targets. It makes bounded GET/HEAD requests, manually validates redirects, records redacted observations, evaluates browser headers/cookie flags/server disclosure/transport context, and writes Markdown and JSON reports. An optional `--llm` mode sends only sanitized observations, checks, and evidence to Gemini. `--multi-agent` uses LangGraph to orchestrate scope, header, cookie, transport, and hub agents; no model receives network tools or authorization authority.

```text
operator URL + local scope.json
            |
            v
 origin, DNS, budget validation ---> bounded HTTP client ---> redacted facts
            |                                |                       |
            +--------------------> deterministic checks <-----------+
                                             |
                                    evidence-linked reports
```

The planner contract and fixed tool allowlist remain isolated modules. The application always owns authorization, argument validation, and network execution. Target HTML and headers are data and never instructions to the scanner.

## Requirements and installation

Python 3.11 or newer. Sentinel uses the Python standard library for runtime operations to keep the safety boundary small and dependency-free. Pytest is only needed for development.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m sentinel --help
```

## Run the local demo

In one terminal:

```bash
python -m sentinel demo
```

It binds only to `127.0.0.1:8000` and exposes `/` and `/health`. The fixture is a training target with intentionally limited header behavior; it contains no secrets or destructive behavior. In another terminal:

```bash
cp scope.example.json scope.json
python -m sentinel validate-scope --scope scope.json
python -m sentinel scan http://127.0.0.1:8000 --scope scope.json --dry-run
python -m sentinel scan http://127.0.0.1:8000 --scope scope.json --output ./artifacts

# Optional LLM interpretation of the collected facts
pip install -e '.[llm]'
export GEMINI_API_KEY='...'
python -m sentinel scan http://127.0.0.1:8000 --scope scope.json --output ./artifacts --llm

# URL-first mode: Sentinel creates an exact temporary scope
python -m sentinel scan https://your-authorized-site.example --authorized --llm

# LangGraph multi-agent mode
pip install -e '.[agents]'
python -m sentinel scan https://your-authorized-site.example --authorized --multi-agent
```

The scan creates `artifacts/report.md` and `artifacts/report.json`. Dry run prints the planned request/checks and sends no network requests.

## Scope and authorization

Scope must enumerate exact origins including scheme and non-default port. See [scope.example.json](scope.example.json). Local/private addresses require `allow_private: true`; that setting is intended for exact local/private origins. Public targets must resolve only to globally routable IPs. Non-loopback targets additionally require `--authorized` on the command line as an explicit operator confirmation. Redirects are never followed automatically: each hop is normalized, checked against the exact origin allowlist, resolved, and checked before another request. Requests stop at configured count, timeout, response size, redirect count, or network deadline per request.

Do not scan a system without permission. Do not put secrets in scope files. Sentinel does not authenticate, test credentials, bypass access controls, crawl external links, or run exploit payloads.

## Reports and interpretation

Reports distinguish raw observations from potential issues. Missing headers receive at most context-limited potential severity; they are not confirmed vulnerabilities by themselves. Cookie values are discarded while flag presence is retained. Evidence identifiers link check outcomes to exact recorded observations. Confidence describes evidence quality, not likelihood of compromise. TLS certificate-chain details are not inspected by the standard-library transport layer.

Known limitations: this is a compact passive scanner, checks one origin/page, does not analyze application-specific behavior, does not perform authenticated testing, and does not provide full certificate validation reporting. DNS is checked before each request, though—as with ordinary clients—DNS can change between validation and the underlying socket connect. For sensitive environments, run from an isolated network with egress controls.

## Configuration

`.env.example` lists placeholder names for the optional Gemini provider and bounded scan settings. LLM use is opt-in; Gemini reads `GEMINI_API_KEY`, or Sentinel can read `SENTINEL_LLM_API_KEY`. Install the optional SDK with `pip install -e '.[llm]'`, select a supported Gemini model with `SENTINEL_LLM_MODEL`, and keep secrets in the environment. Prompts and responses are not logged. The provider receives post-scan facts only and cannot grant itself network access.

## Development

```bash
python -m pytest
```

The suite uses mocked/local loopback HTTP only. No external service is contacted by the tests. The project currently does not configure a formatter, linter, or type checker.

Verification in the implementation environment (Python 3.14): `python -m pytest -q` passed **10 tests**. `python -m sentinel --help`, scope validation, and dry-run succeeded. The demo was started on loopback and scanned end to end; the scan wrote both reports with 8 checks and 8 evidence items. The demo report is included under `outputs/demo-artifacts/`.

## Troubleshooting

- `target origin is not explicitly listed`: add the exact scheme/host/port to the scope.
- `non-loopback target requires --authorized`: add the flag only after confirming permission to test.
- `destination is outside scope or resolves to a prohibited address`: check host resolution and exact scope; prohibited/private destinations are denied unless local/private use is explicitly enabled.
- `request budget exhausted` or response-size error: reduce page content or deliberately adjust the bounded values within the validation limits.
- A failed request still produces a report with a failed check and error summary; inspect the local server and scope.

## Safe-use disclaimer

The operator is responsible for authorization, legal compliance, and safe handling of reports. Sentinel is educational, bounded, and not a substitute for a professional security assessment. A clean scan is not evidence that a target is secure.
