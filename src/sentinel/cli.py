"""Command-line interface."""
import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from sentinel import __version__
from sentinel.checks import evaluate
from sentinel.http_client import BoundedClient
from sentinel.models import ScanResult
from sentinel.reconnaissance import inspect
from sentinel.reporting.json_report import write_json
from sentinel.reporting.markdown import write_markdown
from sentinel.redaction import safe_url
from sentinel.scope import Scope, normalize_url

DISCLAIMER="Only scan systems you own or are explicitly authorized to test. Sentinel is educational and not a substitute for a professional assessment."

def parser():
    p=argparse.ArgumentParser(prog="sentinel",description="Bounded local-first security research scanner")
    sub=p.add_subparsers(dest="command",required=True)
    s=sub.add_parser("scan",help="scan an explicitly scoped origin"); s.add_argument("target"); s.add_argument("--scope"); s.add_argument("--output",default="./artifacts"); s.add_argument("--dry-run",action="store_true"); s.add_argument("--authorized",action="store_true",help="confirm authorization for non-loopback target"); s.add_argument("--llm",action="store_true",help="ask Gemini to analyze collected facts"); s.add_argument("--multi-agent",action="store_true",help="orchestrate scope, header, cookie, transport, and hub agents with LangGraph"); s.add_argument("--model",default=os.getenv("SENTINEL_LLM_MODEL","gemini-2.5-flash"),help="Gemini model used with LLM modes")
    v=sub.add_parser("validate-scope"); v.add_argument("--scope",required=True)
    sub.add_parser("demo",help="run loopback-only demo fixture")
    return p

def main(argv=None):
    args=parser().parse_args(argv)
    try:
        if args.command=="demo":
            from sentinel.demo_app.app import main as demo_main
            demo_main(); return 0
        if args.command == "scan" and not args.scope:
            target_for_scope=normalize_url(args.target)
            scope=Scope([f"{urlsplit(target_for_scope).scheme}://{urlsplit(target_for_scope).netloc}"], allow_private=False, expected_https=urlsplit(target_for_scope).scheme == "https")
        else:
            scope=Scope.load(args.scope)
        if args.command=="validate-scope":
            print(f"Valid scope: {len(scope.origins)} origin(s); {DISCLAIMER}"); return 0
        target=normalize_url(args.target)
        if not any((urlsplit(target).scheme,urlsplit(target).hostname,(urlsplit(target).port or (443 if urlsplit(target).scheme=="https" else 80)))==(urlsplit(x).scheme,urlsplit(x).hostname,(urlsplit(x).port or (443 if urlsplit(x).scheme=="https" else 80))) for x in scope.origins):
            raise ValueError("target origin is not explicitly listed in scope")
        host=urlsplit(target).hostname or ""
        import ipaddress
        is_loopback=host.lower()=="localhost"
        try: is_loopback = is_loopback or ipaddress.ip_address(host).is_loopback
        except ValueError: pass
        if not is_loopback and not args.authorized: raise ValueError("non-loopback target requires --authorized confirmation")
        scan_mode="deterministic+multi-agent" if args.multi_agent else ("deterministic+llm" if args.llm else "deterministic")
        print("Mode: "+scan_mode + (" (dry run)" if args.dry_run else "")); print(DISCLAIMER)
        if args.dry_run:
            llm_step="; LangGraph multi-agent analysis" if args.multi_agent else ("; optional LLM evidence analysis" if args.llm else "")
            print("Planned: one bounded GET reconnaissance request; passive security-header, cookie-flag, server-disclosure, and transport observations"+llm_step+". No network requests sent."); return 0
        start=datetime.now(timezone.utc).isoformat()
        client=BoundedClient(scope)
        response,observation=inspect(client,target)
        checks,evidence=evaluate(response,scope.expected_https)
        llm_analysis=None
        errors=[response.error] if response.error else []
        if (args.llm or args.multi_agent) and not response.error:
            try:
                if args.multi_agent:
                    from sentinel.agent.graph import build_graph
                    graph_result=build_graph().invoke({"target": target, "scope": scope, "observations": [observation], "checks": checks, "evidence": evidence, "model": args.model})
                    llm_analysis=graph_result.get("llm_analysis")
                    errors.extend(graph_result.get("errors", []))
                else:
                    from sentinel.agent.provider import analyze_scan
                    llm_analysis=analyze_scan([observation],checks,evidence,args.model)
            except (RuntimeError, ValueError) as e:
                errors.append(str(e)[:200])
        result=ScanResult("1.0",str(uuid.uuid4()),start,datetime.now(timezone.utc).isoformat(),safe_url(target),{"origins":scope.origins,"allow_private":scope.allow_private},scan_mode,[observation],checks,evidence,errors,llm_analysis)
        out=Path(args.output); out.mkdir(parents=True,exist_ok=True)
        write_json(result,out/"report.json"); write_markdown(result,out/"report.md")
        print(f"Completed: {len(checks)} checks; {sum(c.status=='potential' for c in checks)} potential observations; reports: {out/'report.md'}, {out/'report.json'}")
        return 0 if not errors else 2
    except (ValueError,OSError,json.JSONDecodeError) as e:
        print(f"sentinel: {e}",file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
