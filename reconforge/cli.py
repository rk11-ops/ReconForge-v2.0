from __future__ import annotations
import argparse,asyncio,sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from .config import APP_NAME,APP_VERSION,DEFAULT_TIMEOUT,PROFILES,TESTSSL_REPO_URL
from .models import RunContext
from .utils import normalize_target,validate_existing_file,ensure_directory,enforce_scope,validate_nmap_ports,normalize_nmap_scripts,validate_nmap_script_args,validate_nmap_extra_args,validate_tags,detect_target_kind
from .nse import inventory_nse, inventory_summary, script_spec_for_mode
from .engine.orchestrator import run_assessment

console=Console()

def build_parser():
    p=argparse.ArgumentParser(prog='reconforge',description='ReconForge Advanced Recon Orchestrator')
    p.add_argument('target',nargs='?',help='Authorized URL, hostname or IP')
    p.add_argument('--interactive',action='store_true')
    p.add_argument('--mode',choices=('auto',)+tuple(PROFILES),default='auto')
    p.add_argument('--authorized',action='store_true')
    p.add_argument('--scope')
    p.add_argument('--client'); p.add_argument('--assessment')
    p.add_argument('--output-dir',default='./reconforge-results')
    p.add_argument('--max-parallel',type=int,default=4); p.add_argument('--tool-timeout',type=int,default=DEFAULT_TIMEOUT)
    p.add_argument('--wordlist'); p.add_argument('--fuzzer',choices=('auto','ffuf','feroxbuster'),default='auto')
    p.add_argument('--web-url'); p.add_argument('--no-adaptive',action='store_true'); p.add_argument('--no-diff',action='store_true')
    p.add_argument('--dry-run',action='store_true',help='Show every planned command without starting scanner processes or network probes')
    p.add_argument('--report-format',choices=('ask','html','pdf','none'),default='ask',help='Final report format; ask prompts after the assessment (default).')
    p.add_argument('--report',choices=('ask','yes','no','html','pdf','none'),default=None,help=argparse.SUPPRESS)
    p.add_argument('--report-type',choices=('auto','web','network','api'),default='auto',help='Report template: web, network, or api; auto infers from target')
    p.add_argument('--testssl-path',help=f'Path to testssl.sh executable (official repo: {TESTSSL_REPO_URL})')
    p.add_argument('--passive-depth',type=int,choices=(1,2),default=2)
    p.add_argument('--crawl',dest='crawl',action='store_true',default=True,help='Run bounded same-origin GET crawl for web audit (default: on)')
    p.add_argument('--no-crawl',dest='crawl',action='store_false',help='Disable the web crawler')
    p.add_argument('--crawl-depth',type=int,default=2,help='Maximum same-origin crawl depth (default: 2)')
    p.add_argument('--crawl-pages',type=int,default=50,help='Maximum pages to request during crawl (default: 50)')
    p.add_argument('--crawl-rate',type=float,default=2.0,help='Approximate maximum crawl request rate per second (default: 2)')
    p.add_argument('--crawl-concurrency',type=int,default=4,help='Crawler worker concurrency (default: 4)')
    p.add_argument('--no-audit',dest='audit',action='store_false',default=True,help='Disable built-in safe web audit')
    p.add_argument('--audit-only',action='store_true',help='Run web crawl + safe audit only; skip Nmap/Nikto/Wapiti/Nuclei/fuzzing/SQLMap')
    p.add_argument('--methodology', choices=('all','owasp-top10-2025','cwe-top25-2025'), default='all', help='Methodology mapping and coverage pack (default: all)')
    p.add_argument('--nuclei-tag',action='append',default=[])
    p.add_argument('--sqlmap',choices=('off','auto','force'),default='auto')
    p.add_argument('--qwen-gguf',help='Local Qwen 4B GGUF file or ZIP containing a GGUF')
    p.add_argument('--qwen-bin',help='Path/name of llama-cli executable')
    n=p.add_argument_group('Nmap'); n.add_argument('--nmap-scan-type',choices=('S','T','U','A','W','M')); n.add_argument('--nmap-service',action='store_true'); n.add_argument('--nmap-os',action='store_true'); n.add_argument('--nmap-aggressive',action='store_true'); n.add_argument('--nmap-no-ping',action='store_true'); n.add_argument('--nmap-ports'); n.add_argument('--nmap-web-ports',action='store_true'); n.add_argument('--nmap-script',action='append',default=[]); n.add_argument('--nmap-script-args'); n.add_argument('--nmap-arg',action='append',default=[])
    return p

def resolve_auto_mode(target_kind: str) -> str:
    # Auto mode is intentionally comprehensive but bounded: deep discovery is
    # used for both web and network targets, while the orchestrator decides
    # whether a discovered surface warrants web/TLS follow-up.
    return "deep"

def show_target_plan(target: str, target_kind: str) -> None:
    if target_kind == "api":
        steps = "API discovery -> web crawl -> safe audit -> Nuclei/Wapiti -> parameter review -> bounded validation"
    elif target_kind == "web":
        steps = "Nmap context -> HTTP/TLS probe -> same-origin crawl -> safe audit -> Nuclei/Wapiti -> content discovery -> bounded validation"
    else:
        steps = "Nmap host/service discovery -> detect HTTP/TLS -> safe web audit if exposed -> targeted follow-up"
    console.print(Panel(f"[bold]Target:[/bold] {target}\n[bold]Detected:[/bold] {target_kind}\n[bold]Auto plan:[/bold] {steps}", title="Target-Aware Plan", border_style="red"))

def report_prompt() -> str:
    console.print(Panel("[bold]Assessment complete.[/bold]\nChoose the final report format. The report contains findings only; raw scanner JSON is not embedded.", title="REPORT", border_style="red"))
    return Prompt.ask("Final report", choices=("html", "pdf", "none"), default="html")

def make_context(args):
    if not args.target and not args.interactive:
        args.interactive = True
    if not 1<=args.max_parallel<=16: raise ValueError('--max-parallel must be 1..16')
    if args.tool_timeout<30: raise ValueError('--tool-timeout must be >=30')
    target_value=args.target
    if not target_value:
        args.interactive = True
        target_value=Prompt.ask('Target (URL / API / hostname / IP)')
    if not args.authorized:
        if sys.stdin.isatty() and Confirm.ask('Is this target explicitly authorized for assessment?',default=False):
            args.authorized=True
        else:
            raise PermissionError('Execution blocked: confirm authorization, or pass --authorized for a permitted target.')
    target,host,web=normalize_target(target_value)
    target_kind=detect_target_kind(target, web)
    if args.mode == "auto":
        args.mode = resolve_auto_mode(target_kind)
        console.print(f"[bold red]AUTO MODE[/bold red] -> {args.mode}")
    show_target_plan(target, target_kind)
    if args.web_url:
        _,wh,w=normalize_target(args.web_url)
        if wh.lower()!=host.lower(): raise ValueError('--web-url must use the same host')
        web=w
        target_kind=detect_target_kind(target, web)
    scope=validate_existing_file(args.scope,'Scope file'); enforce_scope(target,host,scope)
    wordlist=validate_existing_file(args.wordlist,'Wordlist')
    out=ensure_directory(args.output_dir); history=out/'.history'; history.mkdir(parents=True,exist_ok=True)
    ports='80,443' if args.nmap_web_ports else validate_nmap_ports(args.nmap_ports)
    if args.nmap_web_ports and args.nmap_ports: raise ValueError('Use only one of --nmap-web-ports/--nmap-ports')
    # A URL/host:port should drive a focused Nmap port when the operator did not
    # explicitly choose a port set. This keeps direct URL targets useful in all modes.
    if ports is None and web:
        from urllib.parse import urlparse
        try:
            target_port=urlparse(web).port
        except ValueError as exc:
            raise ValueError(f'Invalid target port: {exc}')
        if target_port:
            ports=str(target_port)
    qwen=validate_existing_file(args.qwen_gguf,'Qwen GGUF/ZIP') if args.qwen_gguf else None
    testssl_path=validate_existing_file(args.testssl_path,'testssl.sh') if args.testssl_path else None
    nmap_scripts=normalize_nmap_scripts(args.nmap_script) if args.nmap_script else (script_spec_for_mode(args.mode),)
    crawl_depth=getattr(args,'crawl_depth',2)
    crawl_pages=getattr(args,'crawl_pages',50)
    crawl_rate=getattr(args,'crawl_rate',2.0)
    crawl_concurrency=getattr(args,'crawl_concurrency',4)
    crawl_enabled=getattr(args,'crawl',True)
    audit_enabled=getattr(args,'audit',True)
    audit_only=getattr(args,'audit_only',False)
    if not 0 <= crawl_depth <= 8: raise ValueError('--crawl-depth must be 0..8')
    if not 1 <= crawl_pages <= 1000: raise ValueError('--crawl-pages must be 1..1000')
    if not 0.1 <= crawl_rate <= 25: raise ValueError('--crawl-rate must be 0.1..25')
    if not 1 <= crawl_concurrency <= 12: raise ValueError('--crawl-concurrency must be 1..12')
    report_arg=getattr(args,'report',None)
    report_format=('ask' if report_arg == 'ask' else 'html' if report_arg == 'yes' else 'none' if report_arg in {'no','none'} else report_arg if report_arg in {'html','pdf'} else getattr(args,'report_format','ask'))
    ctx=RunContext(target=target,host=host,web_url=web,target_kind=target_kind,mode=args.mode,output_dir=out,history_root=history,tool_timeout=args.tool_timeout,max_parallel=args.max_parallel,fuzzer=args.fuzzer,custom_wordlist=wordlist,nmap_scan_type=args.nmap_scan_type,nmap_service_version=args.nmap_service,nmap_os_detection=args.nmap_os,nmap_aggressive=args.nmap_aggressive,nmap_no_ping=args.nmap_no_ping,nmap_ports=ports,nmap_scripts=nmap_scripts,nmap_script_args=validate_nmap_script_args(args.nmap_script_args),nmap_extra_args=validate_nmap_extra_args(args.nmap_arg),nuclei_tags=validate_tags(args.nuclei_tag),scope_attested=True,scope_file=scope,client_name=args.client,assessment_name=args.assessment,adaptive=not args.no_adaptive,diff_enabled=not args.no_diff,adaptive_budget=PROFILES[args.mode].adaptive_budget,sqlmap_mode=args.sqlmap,qwen_gguf=qwen,qwen_bin=args.qwen_bin,report_enabled=(report_format != 'none'),dry_run=args.dry_run,passive_depth=args.passive_depth,report_type=args.report_type,testssl_path=testssl_path,crawl_enabled=crawl_enabled,audit_enabled=audit_enabled,audit_only=audit_only,crawl_depth=crawl_depth,crawl_pages=crawl_pages,crawl_rate=crawl_rate,crawl_concurrency=crawl_concurrency,methodology=getattr(args,'methodology','all'),report_format=report_format)
    return ctx

def banner():
    art = r"""
  ____  _____ ____ ___  _   _ _____ ___  ____   ___  ____   ____  _____
 |  _ \| ____/ ___/ _ \| \ | |  ___/ _ \|  _ \ / _ \|  _ \| ____|
 | |_) |  _|| |  | | | |  \| | |_ | | | | | |_) | | | | |_) |  _|
 |  _ <| |__| |__| |_| | |\  |  _|| |_| | |  _ <| |_| |  _ <| |___
 |_| \_\_____\____\___/|_| \_|_|   \___/|_| \_\_\___/|_| \_\|_____|
"""
    console.print(Panel.fit(Text(art, style="bold red"), title="OFFENSIVE RECON OPERATIONS", subtitle="evidence-driven / operator-controlled", border_style="red", padding=(0,2)))
    console.print("[bold white]RECONFORGE[/bold white] [dim]Adaptive Security Assessment Engine[/dim]")

def preflight_tools():
    import shutil
    checks=[('nmap','nmap'),('nikto','nikto'),('wapiti','wapiti'),('nuclei','nuclei'),('sqlmap','sqlmap'),('ffuf','ffuf'),('feroxbuster','feroxbuster'),('testssl.sh','testssl.sh'),('llama-cli','llama-cli')]
    table=Table(title='Toolchain Preflight'); table.add_column('Tool'); table.add_column('Status')
    for label,exe in checks:
        table.add_row(label, '[green]READY[/green]' if shutil.which(exe) else '[yellow]NOT INSTALLED[/yellow]')
    console.print(table)
    console.print(inventory_summary(inventory_nse()))

def main():
    args=build_parser().parse_args();
    if not args.target:
        args.interactive=True
    banner()
    try:
        ctx=make_context(args)
        preflight_tools()
        console.print(Panel(f'Target: {ctx.target}\nDetected type: {ctx.target_kind}\nMode: {ctx.mode}\nReport type: {ctx.report_type}\nAdaptive: {ctx.adaptive}\nWeb crawl: {ctx.crawl_enabled} (depth={ctx.crawl_depth}, pages={ctx.crawl_pages})\nSafe audit: {ctx.audit_enabled}\nAudit-only: {ctx.audit_only}\nMethodology: {ctx.methodology}\nSQLMap: {ctx.sqlmap_mode}\nTestSSL: {ctx.testssl_path or "auto-discover"}\nQwen GGUF: {ctx.qwen_gguf or "off"}\nDry-run: {ctx.dry_run}',title='Preflight',border_style='blue'))
        if args.dry_run: console.print('[yellow]DRY-RUN: no scanner process and no passive network request will be started.[/yellow]')
        report,paths=asyncio.run(run_assessment(ctx,lambda s: console.print(f'[bold]{s}[/bold]'), report_choice=report_prompt))
        table=Table(title='Final Summary'); table.add_column('Metric'); table.add_column('Value')
        table.add_row('Reportable findings',str(len(report.get('findings',[])))); table.add_row('Suppressed candidates',str(len(report.get('not_reported',[])))); table.add_row('Ports',str(len(report.get('attack_surface',{}).get('ports',[])))); table.add_row('Endpoints',str(len(report.get('attack_surface',{}).get('endpoints',[])))); table.add_row('Report', str(next(iter(paths.values())) if paths else 'not generated')); console.print(table)
        return 0
    except KeyboardInterrupt: console.print('[yellow]Interrupted.[/yellow]'); return 130
    except (ValueError,PermissionError) as e: console.print(f'[red]Error:[/red] {e}'); return 2
    except Exception as e: console.print(f'[red]Fatal:[/red] {e}'); return 1
