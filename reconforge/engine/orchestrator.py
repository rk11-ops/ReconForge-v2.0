from __future__ import annotations
import asyncio
from datetime import datetime,timezone
from typing import Any
from ..config import PROFILES
from ..models import AdaptiveAction
from ..scanners import NmapScanner,NiktoRunner,WapitiRunner,NucleiRunner,FuzzerEngine,SQLMapRunner,TestSSLRunner
from ..scanners.http_probe import PassiveHTTPProbe
from ..audit.crawler import WebCrawler
from ..evidence.engine import EvidenceEngine
from ..adaptive.decision_engine import AdaptiveDecisionEngine
from ..adaptive.rules import web_service_found
from ..utils import primary_web_url, detect_target_kind, format_host_for_url
from ..validation.findings import validate_findings
from ..engine.scheduler import execute_sequential
from ..engine.state import AssessmentState
from ..engine.lifecycle import create_run,load_latest_snapshot,save_latest_snapshot,make_snapshot,snapshot_diff,write_artifact_manifest
from ..reporting.builder import build_report
from ..reporting.html import write_reports
from ..reporting.pdf import write_pdf_report
from ..ai.qwen import run_qwen_gguf
from ..methodology import build_methodology_coverage, apply_methodology_annotations

FIREWALL_HINTS = (
    'firewall',
    'intrusion',
    ' ids',
    'ips ',
    'rate limit',
    'too many',
    'host seems down',
    'packet dropped',
    'admin prohibited',
    'waf',
)

def firewall_or_ids_suspected(results) -> bool:
    nmap_results = [r for r in results if r.tool == 'nmap']
    for result in nmap_results:
        summary = result.summary if isinstance(result.summary, dict) else {}
        if float(summary.get('filtered_ratio') or 0) >= 0.60:
            return True
        blob = ' '.join(
            [
                str(result.stdout_tail or ''),
                str(result.stderr_tail or ''),
                ' '.join(str(x) for x in (result.notes or [])),
            ]
        ).lower()
        if any(token in blob for token in FIREWALL_HINTS):
            return True
    return False

async def execute_parallel(scanners, max_parallel, phase, state):
    from ..engine.scheduler import execute_scanners
    return await execute_scanners(scanners, max_parallel, phase, state)


def fallback_web_url(host: str) -> list[str]:
    formatted = format_host_for_url(host)
    return [f'https://{formatted}', f'http://{formatted}']


def tls_target_from_analysis(ctx, analysis):
    if str(ctx.web_url).lower().startswith('https://'):
        return ctx.web_url
    ports = analysis.get('attack_surface',{}).get('ports',[]) if isinstance(analysis,dict) else []
    for item in ports:
        if not isinstance(item,dict) or str(item.get('state')) != 'open':
            continue
        port=str(item.get('port') or '')
        service=str(item.get('service') or '').lower()
        if port in {'443','444','465','636','853','993','995','8443','9443'} or service in {'https','ssl/http','imaps','pop3s','ldaps'} or 'ssl' in service or 'tls' in service:
            return f'{ctx.host}:{port}'
    return None

def build_scanners(ctx,stage='initial',analysis=None):
    if stage=='recon': return [NmapScanner(ctx)]
    if stage=='web':
        out=[]
        # Visible fixed order: server checks -> TLS -> web vuln -> templates -> content discovery.
        out.append(NiktoRunner(ctx))
        tls_target = tls_target_from_analysis(ctx, analysis or {})
        if tls_target:
            out.append(TestSSLRunner(ctx, target=tls_target))
        out.append(WapitiRunner(ctx)); out.append(NucleiRunner(ctx,tags=ctx.nuclei_tags)); out.append(FuzzerEngine(ctx)); return out
    return []

def scanners_for_actions(ctx,actions):
    out=[]
    for a in actions:
        if a.type=='nuclei': out.append(NucleiRunner(ctx,tags=a.tags))
        elif a.type=='wapiti': out.append(WapitiRunner(ctx))
        elif a.type=='nikto': out.append(NiktoRunner(ctx))
        elif a.type=='fuzzer': out.append(FuzzerEngine(ctx,base_path=a.base_path,label=a.label))
        elif a.type=='sqlmap' and ctx.sqlmap_mode!='off' and a.target_url:
            out.append(SQLMapRunner(ctx,a.target_url))
    return out

def sqlmap_candidate_urls(analysis):
    urls=[]
    for ep in analysis.get('attack_surface',{}).get('endpoints',[]):
        if '?' in str(ep): urls.append(str(ep))
    return urls[:3]

async def run_assessment(ctx,console_print=print,report_choice=None):
    scan_id=create_run(ctx); state=AssessmentState(ctx,scan_id); state.transition('preflight')
    start=datetime.now(timezone.utc).isoformat()
    ctx.__dict__['adaptive_budget']=PROFILES[ctx.mode].adaptive_budget
    console_print('\n=== STAGE 1/6 • RECON DISCOVERY ===')
    state.transition('recon')
    passive={'status':'dry-run'} if ctx.dry_run else {}
    if ctx.audit_only:
        console_print('AUDIT-ONLY > network and external scanner stages are disabled; web audit will remain GET-only.')
        results=[]
        analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()
    else:
        recon_scanners=build_scanners(ctx,'recon'); results=await execute_parallel(recon_scanners, ctx.max_parallel, 'recon', state)
        analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()
    console_print(f'TARGET > initial classification: {ctx.target_kind}')

    # Auto-detect web/API exposure after network discovery.
    from urllib.parse import urlparse
    base_http=f"http://{format_host_for_url(ctx.host)}"
    # Treat an explicit URL or a schemeless host:port / --web-url as an explicit web surface.
    try:
        explicit_port=urlparse(ctx.web_url).port is not None
    except ValueError:
        explicit_port=False
    explicit_web = str(ctx.target).lower().startswith(('http://','https://')) or str(ctx.web_url).rstrip('/') != base_http.rstrip('/') or explicit_port
    auto_web=primary_web_url(ctx.host, analysis.get('attack_surface',{}).get('ports',[]), ctx.web_url if explicit_web else None)
    if auto_web:
        ctx.web_url=auto_web
        ctx.target_kind=detect_target_kind(ctx.target, auto_web)
        console_print(f'TARGET > web surface discovered: {ctx.web_url} ({ctx.target_kind})')
        passive={'status':'dry-run'} if ctx.dry_run else await PassiveHTTPProbe(ctx).run()
        analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()

    # Heavy filtering/IDS gets a slower -T3 retry plus Nmap -A, not a firewall bypass.
    if ctx.dry_run or firewall_or_ids_suspected(results):
        if ctx.dry_run:
            console_print('ADAPTIVE PREVIEW > If filtering/IDS is detected, ReconForge retries at -T3 with -A.')
        else:
            console_print('ADAPTIVE > Firewall/IDS/filtering suspected from Nmap; retrying discovery at -T3 with aggressive (-A) scan.')
        retry=NmapScanner(ctx,timing_override=3,artifact_suffix='-t3-retry',force_aggressive=True)
        if ctx.dry_run:
            preview,_=retry.build_command()
            console_print('COMMAND > ' + retry.command_text(preview))
        else:
            results.extend(await execute_sequential([retry],'recon-retry',state))
            analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()
            auto_web=primary_web_url(ctx.host, analysis.get('attack_surface',{}).get('ports',[]), ctx.web_url if explicit_web else None)
            if auto_web:
                ctx.web_url=auto_web
                ctx.target_kind=detect_target_kind(ctx.target, auto_web)

    if not auto_web:
        probe=PassiveHTTPProbe(ctx)
        for candidate in fallback_web_url(ctx.host):
            if ctx.dry_run:
                auto_web=candidate
                ctx.web_url=candidate
                ctx.target_kind=detect_target_kind(ctx.target, candidate)
                console_print(f'TARGET > no open web ports yet; will still validate HTTP/TLS surface at {candidate}')
                break
            hit=probe._fetch(candidate)
            if hit.get('status')=='completed' and hit.get('http_status'):
                auto_web=candidate
                ctx.web_url=candidate
                ctx.target_kind=detect_target_kind(ctx.target, candidate)
                console_print(f'TARGET > HTTP/TLS responded at {candidate}; enabling nikto/testssl/wapiti')
                passive=hit
                analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()
                break

    console_print('\n=== STAGE 2/6 • WEB CRAWL + SAFE AUDIT ===')
    state.transition('web')
    if auto_web and ctx.crawl_enabled and ctx.audit_enabled:
        crawler = WebCrawler(ctx)
        crawl_result = await crawler.run()
        results.append(crawl_result)
        crawl_summary = crawl_result.summary.get('crawl', {}) if isinstance(crawl_result.summary, dict) else {}
        console_print(f"AUDIT > crawled {crawl_summary.get('pages_crawled', 0)} page(s); observed {len(crawl_summary.get('findings', []))} safe audit signal(s).")
        analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()
    if ctx.audit_only:
        web_results=[]
    else:
        web_scanners=build_scanners(ctx,'web',analysis) if auto_web or ctx.dry_run else []
        web_results=await execute_parallel(web_scanners, ctx.max_parallel, 'web', state)
    results.extend(web_results); analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()

    console_print('\n=== STAGE 3/6 • ADAPTIVE FOLLOW-UP ===')
    state.transition('adaptive')
    completed={r.tool for r in results if r.status in {'completed','dry-run'}}
    actions=[] if ctx.audit_only else AdaptiveDecisionEngine.decide(ctx,analysis,completed); state.actions.extend([a.__dict__ for a in actions]); state.save()
    for a in actions: console_print(f'ADAPTIVE > [{a.priority}] {a.type}: {a.reason}')
    adaptive_results=[] if ctx.audit_only else await execute_parallel(scanners_for_actions(ctx,actions), ctx.max_parallel, 'adaptive', state)
    results.extend(adaptive_results); analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis; state.save()

    console_print('\n=== STAGE 4/6 • SAFE VALIDATION + PoC GATE ===')
    state.transition('validate')
    # SQLMap runs before final validation so its evidence participates in correlation.
    # Adaptive SQLMap actions already cover parameterized discovered URLs. For force mode,
    # run at most two bounded checks when no candidate was discovered.
    if (not ctx.audit_only) and ctx.sqlmap_mode=='force' and not any(r.tool=='sqlmap' for r in results):
        urls=sqlmap_candidate_urls(analysis) or ([ctx.web_url] if ctx.web_url else [])
        for url in urls[:2]:
            results.extend(await execute_parallel([SQLMapRunner(ctx,url)],ctx.max_parallel,'sqlmap',state))
        analysis=EvidenceEngine.analyze(ctx,results,passive); state.analysis=analysis
    validations=validate_findings(ctx,analysis); state.validation=validations; state.save()
    for f in analysis.get('findings',[]):
        v=next((x for x in validations if x['fingerprint']==f['fingerprint']),None)
        if v: f.update(v)

    console_print('\n=== STAGE 5/6 • QUALITY GATE + CORRELATION ===')
    state.transition('quality-gate')
    reportable=[]; not_reported=[]
    reportable_statuses={'confirmed','corroborated','scanner-reported','needs-validation'}
    suppressed_statuses={'not-reproduced','false-positive','error','not-applicable'}
    for f in analysis.get('findings',[]):
        status=f.get('validation_status','unverified')
        evidence_state=f.get('evidence_state','SCANNER_REPORTED')
        if status in reportable_statuses or evidence_state in {'CONFIRMED_OBSERVED','CONFIRMED_DERIVED','SCANNER_REPORTED','NEEDS_VALIDATION'}:
            f['report_disposition']='report'
            # Keep scanner/validation semantics explicit instead of hiding the issue.
            if status not in reportable_statuses:
                f['validation_status']='needs-validation'
                f['validation_reason']=f.get('validation_reason') or 'Observed by scanner pipeline; vulnerability-specific validation remains outstanding.'
            reportable.append(f)
        elif status in suppressed_statuses:
            f['report_disposition']='suppressed'
            not_reported.append({'candidate':f.get('name'),'severity':f.get('severity'),'status':status,'reason':f.get('validation_reason') or 'Validation did not reproduce the candidate.'})
        else:
            f['report_disposition']='candidate'
            f['validation_status']='needs-validation'
            f['validation_reason']=f.get('validation_reason') or 'Evidence exists but vulnerability-specific validation is still required.'
            reportable.append(f)
    analysis['reportable_findings']=reportable; analysis['not_reported']=not_reported
    # Map every normalized finding to the current OWASP Top 10:2025 / CWE Top 25:2025 packs.
    analysis['findings'] = apply_methodology_annotations(analysis.get('findings', []))
    analysis['reportable_findings'] = apply_methodology_annotations(analysis.get('reportable_findings', []))
    web_audit_pages = (analysis.get('web_audit') or {}).get('pages', []) if isinstance(analysis.get('web_audit'), dict) else []
    analysis['methodology'] = build_methodology_coverage(
        findings=analysis.get('findings', []),
        pages=web_audit_pages,
        selected=getattr(ctx, 'methodology', 'all'),
    )

    diff={'disabled':True}
    if ctx.diff_enabled:
        snap=make_snapshot(analysis); previous=load_latest_snapshot(ctx.history_root,ctx.host); diff=snapshot_diff(previous,snap); save_latest_snapshot(ctx.history_root,ctx.host,snap,scan_id)
        state.event('diff',added=diff.get('added',{}),removed=diff.get('removed',{}))

    console_print('\n=== STAGE 6/6 • REPORTING ===')
    state.transition('report')
    end=datetime.now(timezone.utc).isoformat()
    qwen_result=None
    if ctx.qwen_gguf:
        qwen_result=run_qwen_gguf(ctx,analysis,console_print)
    report=build_report(ctx,results,start,end,analysis,diff,actions,scan_id,qwen_result)

    # Report generation is deliberately interactive by default. The scan completes
    # first, then the operator chooses HTML, PDF, or no final report.
    fmt=getattr(ctx,'report_format','ask')
    if ctx.dry_run:
        fmt='none'
    elif fmt=='ask':
        fmt=report_choice() if report_choice else 'html'
    paths={}
    if fmt=='html':
        paths=write_reports(report,ctx.output_dir,html_enabled=True)
    elif fmt=='pdf':
        paths={'pdf':write_pdf_report(report,ctx.output_dir)}
    elif fmt=='none':
        console_print('REPORT > skipped by operator.')
    else:
        raise ValueError(f'Unsupported report format: {fmt}')

    manifest=write_artifact_manifest(ctx.output_dir)
    report['evidence_manifest']=manifest
    state.event('artifact_manifest',count=manifest.get('count',0),path=str(ctx.output_dir/'evidence'/'manifest.json'))
    state.transition('complete',report=str(next(iter(paths.values())) if paths else 'reports-skipped'))
    return report,paths
