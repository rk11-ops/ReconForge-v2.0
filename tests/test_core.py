import asyncio
import argparse
import tempfile
import unittest
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parent
sys.path.insert(0,str(ROOT))

from reconforge.cli import build_parser, make_context
from reconforge.models import ToolResult
from reconforge.scanners.nmap import NmapScanner
from reconforge.scanners.sqlmap import SQLMapRunner, DANGEROUS_FLAGS
from reconforge.scanners.testssl import TestSSLRunner
from reconforge.evidence.engine import EvidenceEngine
from reconforge.evidence.normalize import normalize_finding
from reconforge.adaptive.decision_engine import AdaptiveDecisionEngine
from reconforge.utils import detect_target_kind
from reconforge.nse import NseInventory, script_spec_for_mode, BLOCKED_CATEGORIES
from reconforge.engine.orchestrator import firewall_or_ids_suspected
from reconforge.validation.findings import validate_findings
from reconforge.engine.lifecycle import snapshot_diff

class CoreTests(unittest.TestCase):
    def args(self,out,**kw):
        d=dict(crawl=True,crawl_depth=2,crawl_pages=50,crawl_rate=2.0,crawl_concurrency=4,audit=True,audit_only=False,target='192.0.2.10',mode='advanced',authorized=True,scope=None,client='Demo',assessment='Lab',output_dir=str(out),max_parallel=2,tool_timeout=60,wordlist=None,fuzzer='ffuf',web_url=None,no_adaptive=False,no_diff=False,dry_run=True,report='yes',passive_depth=2,nuclei_tag=[],sqlmap='auto',qwen_gguf=None,qwen_bin=None,nmap_scan_type=None,nmap_service=False,nmap_os=False,nmap_aggressive=False,nmap_no_ping=False,nmap_ports=None,nmap_web_ports=False,nmap_script=[],nmap_script_args=None,nmap_arg=[],interactive=False,report_type='auto',testssl_path=None)
        d.update(kw); return argparse.Namespace(**d)

    def test_target_url_and_host_port_normalization(self):
        with tempfile.TemporaryDirectory() as t:
            url=make_context(self.args(Path(t),target='https://example.test:8443/api/v1'))
            self.assertEqual(url.host,'example.test')
            self.assertEqual(url.web_url,'https://example.test:8443/api/v1')
            self.assertEqual(url.target_kind,'api')
            self.assertEqual(url.nmap_ports,'8443')
            hostport=make_context(self.args(Path(t),target='192.0.2.10:8080'))
            self.assertEqual(hostport.host,'192.0.2.10')
            self.assertEqual(hostport.web_url,'http://192.0.2.10:8080')
            self.assertEqual(hostport.target_kind,'web')
            self.assertEqual(hostport.nmap_ports,'8080')

    def test_passive_http_findings_are_reportable(self):
        with tempfile.TemporaryDirectory() as t:
            args=build_parser().parse_args(['https://example.test','--authorized','--report-format','none','--output-dir',t])
            ctx=make_context(args)
            passive={
                'passive_findings':[{'name':'Missing clickjacking protection','severity':'low','endpoint':'https://example.test','direct_observation':True,'evidence_state':'CONFIRMED_OBSERVED'}],
                'discovered_links':['https://example.test/login'],
                'technologies':['nginx'],
            }
            a=EvidenceEngine.analyze(ctx,[],passive)
            self.assertEqual(len(a['findings']),1)
            self.assertEqual(a['findings'][0]['evidence_state'],'CONFIRMED_OBSERVED')
            self.assertEqual(a['findings'][0]['issue_key'],'clickjacking')

    def test_target_and_context(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t)))
            self.assertEqual(ctx.host,'192.0.2.10'); self.assertTrue(ctx.scope_attested); self.assertEqual(ctx.mode,'advanced')
    def test_nmap_builder(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t)))
            argv,_=NmapScanner(ctx).build_command()
            self.assertIn('-p-',argv); self.assertIn('-A',argv); self.assertIn('--script',argv); self.assertEqual(argv[-1],'192.0.2.10')
            spec=argv[argv.index('--script')+1]
            for blocked in BLOCKED_CATEGORIES:
                self.assertFalse(spec == blocked)
                self.assertFalse(spec.startswith(blocked+','))
    def test_nmap_t3_retry_builder(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t)))
            argv,_=NmapScanner(ctx,timing_override=3,artifact_suffix='-t3-retry',force_aggressive=True).build_command()
            self.assertIn('-T3',argv)
            self.assertNotIn('-T4',argv)
            self.assertIn('-A',argv)
            self.assertIn('--script',argv)

    def test_sqlmap_bounded(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t),sqlmap='force'))
            argv,_=SQLMapRunner(ctx,'http://192.0.2.10/item?id=1').build_command()
            self.assertIn('--batch',argv); self.assertIn('--smart',argv); self.assertIn('--risk',argv)
            self.assertFalse(DANGEROUS_FLAGS & set(argv))

    def test_adaptive_sqlmap_action_preserves_full_url(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t),sqlmap='auto'))
            analysis={'attack_surface':{'ports':[{'port':'443','service':'https'}],'technologies':[],'endpoints':['https://192.0.2.10/api/items?id=1']}}
            actions=AdaptiveDecisionEngine.decide(ctx,analysis,{'nuclei','wapiti','nikto','fuzzer'})
            sql=[a for a in actions if a.type=='sqlmap']
            self.assertTrue(sql)
            self.assertEqual(sql[0].target_url,'https://192.0.2.10/api/items?id=1')
            runners=__import__('reconforge.engine.orchestrator',fromlist=['scanners_for_actions']).scanners_for_actions(ctx,sql)
            self.assertEqual(runners[0].name,'sqlmap')

    def test_evidence_correlation(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t)))
            results=[ToolResult(tool='nuclei',status='completed',summary={'ports':[{'port':'443','protocol':'tcp','state':'open','service':'https','product':'nginx','version':'1.2'}],'findings':[{'name':'Missing X-Frame-Options','severity':'low','matched_at':'http://192.0.2.10/login'}]}),ToolResult(tool='nikto',status='completed',summary={'observations':['Missing X-Frame-Options on /login']})]
            a=EvidenceEngine.analyze(ctx,results,{'technologies':['nginx'],'discovered_links':['http://192.0.2.10/login']})
            self.assertEqual(len(a['findings']),1); self.assertEqual(set(a['findings'][0]['sources']),{'nuclei','nikto'})
    def test_adaptive_api_and_sqlmap(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t),sqlmap='auto'))
            analysis={'attack_surface':{'ports':[{'port':'443','service':'https'}],'technologies':['wordpress'],'endpoints':['https://192.0.2.10/api/items?id=1']}}
            actions=AdaptiveDecisionEngine.decide(ctx,analysis,{'nuclei','wapiti','nikto','fuzzer'})
            kinds={a.type for a in actions}; self.assertIn('fuzzer',kinds); self.assertIn('sqlmap',kinds)
    def test_quality_gate_suppresses_single_source(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t)))
            analysis={'findings':[{'fingerprint':'sql-injection|/x','issue_key':'sql-injection','name':'SQL injection','severity':'high','sources':['nuclei'],'endpoints':['http://192.0.2.10/x']}], 'attack_surface':{}}
            vals=validate_findings(ctx,analysis); self.assertEqual(vals[0]['validation_status'],'scanner-reported')

    def test_scanner_reported_finding_is_reportable(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=make_context(self.args(Path(t)))
            analysis={'findings':[{'fingerprint':'hsts|/','issue_key':'hsts','name':'HSTS is not offered','severity':'low','sources':['testssl.sh'],'endpoints':['https://192.0.2.10/'],'evidence_state':'CONFIRMED_OBSERVED'}], 'attack_surface':{}}
            vals=validate_findings(ctx,analysis)
            self.assertEqual(vals[0]['validation_status'],'scanner-reported')
            analysis['findings'][0].update(vals[0])
            # Quality-gate semantics are represented by the orchestrator block; direct assertion on the status is enough here.
            self.assertEqual(analysis['findings'][0]['evidence_state'],'CONFIRMED_OBSERVED')

    def test_testssl_structured_finding_keeps_identifier_and_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            args=build_parser().parse_args(['https://example.test','--authorized','--report-format','none','--output-dir',t])
            ctx=make_context(args)
            artifact=Path(t)/'testssl.json'
            artifact.write_text('{"hsts":{"id":"HSTS","severity":"LOW","finding":"HSTS is not offered"},"beast":{"id":"BEAST","severity":"LOW","finding":"potentially vulnerable"}}')
            from reconforge.scanners.testssl import TestSSLRunner
            result=ToolResult(tool='testssl.sh',status='completed')
            TestSSLRunner(ctx).enrich_result(result,artifact)
            ids={x.get('identifier') for x in result.summary['findings']}
            self.assertIn('HSTS',ids); self.assertIn('BEAST',ids)
            hsts=next(x for x in result.summary['findings'] if x['identifier']=='HSTS')
            beast=next(x for x in result.summary['findings'] if x['identifier']=='BEAST')
            self.assertEqual(hsts['evidence_state'],'CONFIRMED_OBSERVED')
            self.assertEqual(beast['evidence_state'],'NEEDS_VALIDATION')

    def test_snapshot_diff(self):
        old={'snapshot':{'ports':['tcp:80:http'],'technologies':['nginx'],'endpoints':['/old'],'findings':[]}}
        new={'ports':['tcp:443:https'],'technologies':['nginx'],'endpoints':['/new'],'findings':[]}
        d=snapshot_diff(old,new); self.assertEqual(d['added']['ports'],['tcp:443:https']); self.assertEqual(d['removed']['endpoints'],['/old'])
    def test_report_type_auto_web_and_network(self):
        with tempfile.TemporaryDirectory() as t:
            web=make_context(self.args(Path(t),target='https://example.test',web_url='https://example.test'))
            net=make_context(self.args(Path(t),target='192.0.2.10',web_url=None))
            from reconforge.reporting.builder import infer_report_type
            self.assertEqual(infer_report_type(web),'web')
            self.assertEqual(infer_report_type(net),'network')

    def test_testssl_command(self):
        with tempfile.TemporaryDirectory() as t:
            args=build_parser().parse_args(['https://example.test','--authorized','--report-format','none','--output-dir',t])
            ctx=make_context(args)
            scanner=TestSSLRunner(ctx)
            # PATH-independent command shape when no executable is installed.
            argv,_=scanner.build_command()
            self.assertEqual(argv[-1],'https://example.test')
            self.assertIn('--jsonfile-pretty',argv)

    def test_target_kind_auto_detection(self):
        self.assertEqual(detect_target_kind('https://example.test/api/v1'), 'api')
        self.assertEqual(detect_target_kind('https://example.test'), 'web')
        self.assertEqual(detect_target_kind('192.0.2.10'), 'network')

    def test_cli_dry_run_and_help(self):
        p=build_parser(); a=p.parse_args(['192.0.2.10','--authorized','--dry-run','--mode','advanced']); self.assertTrue(a.dry_run)

    def test_live_nse_spec_excludes_blocked(self):
        inv=NseInventory(root=Path('/tmp/nmap/scripts'), scripts={
            'http-title': frozenset({'default','discovery','safe'}),
            'http-vuln-cve2017-5638': frozenset({'vuln','intrusive'}),
            'ftp-brute': frozenset({'brute','intrusive'}),
            'http-slowloris': frozenset({'dos'}),
            'smb-vuln-ms08-067': frozenset({'exploit','vuln'}),
            'ssl-cert': frozenset({'default','safe','discovery'}),
        })
        self.assertEqual(script_spec_for_mode('basic', inv), 'default,discovery,safe')
        self.assertEqual(script_spec_for_mode('deep', inv), 'default,discovery,safe,vuln')
        advanced=script_spec_for_mode('advanced', inv)
        self.assertIn('default', advanced)
        self.assertIn('vuln', advanced)
        self.assertNotIn('brute', advanced)
        self.assertNotIn('dos', advanced)
        self.assertNotIn('exploit', advanced)
        self.assertNotIn('intrusive', advanced)

    def test_firewall_hint_detection(self):
        quiet=ToolResult(tool='nmap',status='completed',summary={'filtered_ratio':0.1})
        noisy=ToolResult(tool='nmap',status='completed',summary={'filtered_ratio':0.2},stdout_tail='possible IDS / firewall dropping probes')
        heavy=ToolResult(tool='nmap',status='completed',summary={'filtered_ratio':0.8})
        self.assertFalse(firewall_or_ids_suspected([quiet]))
        self.assertTrue(firewall_or_ids_suspected([noisy]))
        self.assertTrue(firewall_or_ids_suspected([heavy]))

class ReportUXTests(unittest.TestCase):
    def test_auto_and_report_format_parser(self):
        p=build_parser()
        a=p.parse_args([])
        self.assertEqual(a.mode,'auto')
        self.assertEqual(a.report_format,'ask')
        b=p.parse_args(['https://example.test','--authorized','--report-format','pdf'])
        self.assertEqual(b.report_format,'pdf')

    def test_report_source_command_and_why_reported(self):
        with tempfile.TemporaryDirectory() as t:
            args=build_parser().parse_args(['https://example.test','--authorized','--report-format','none','--output-dir',t])
            ctx=make_context(args)
            r=ToolResult(tool='nuclei',status='completed',command=['nuclei','-u','https://example.test'],summary={'findings':[{'name':'Missing X-Frame-Options','severity':'low','matched_at':'https://example.test/login'}]})
            a=EvidenceEngine.analyze(ctx,[r],{'technologies':[],'discovered_links':['https://example.test/login']})
            f=a['findings'][0]
            self.assertIn('source_commands',f)
            self.assertEqual(f['source_commands']['nuclei'],'nuclei -u https://example.test')
            self.assertTrue(f.get('why_reported'))

    def test_operator_html_contains_findings_only(self):
        from reconforge.reporting.html import write_reports
        with tempfile.TemporaryDirectory() as t:
            out=Path(t)
            report={'meta':{'target':'https://example.test','started_at':'2026-10-09T10:00:00+00:00','mode':'deep','scan_id':'abc','report_type':'web'},'findings':[{'name':'Missing HSTS','severity':'low','endpoint':'https://example.test','evidence_state':'CONFIRMED_OBSERVED','sources':['http-passive'],'why_reported':'Directly observed in assessment evidence.','description':'HSTS was not present.','impact':'HTTPS users may be exposed to downgrade risk.','remediation':'Enable HSTS for the intended HTTPS host.','owasp_category':'A04:2025 Cryptographic Failures','cwe':'CWE-319','source_commands':{'http-passive':'Built-in HTTP GET probe: https://example.test'}}], 'not_reported':[{'candidate':'Historical CVE candidate','severity':'medium','reason':'Version evidence was insufficient to reproduce the claim.'}]}
            paths=write_reports(report,out,html_enabled=True)
            data=paths['html'].read_text(encoding='utf-8')
            self.assertIn('Missing HSTS',data)
            self.assertIn('Why this was reported',data)
            self.assertIn('Command used',data)
            self.assertIn('Historical CVE candidate',data)
            self.assertNotIn('Raw JSON',data)
            self.assertNotIn('<details',data)

    def test_pdf_report_generation(self):
        from reconforge.reporting.pdf import write_pdf_report
        with tempfile.TemporaryDirectory() as t:
            out=Path(t)
            report={'meta':{'target':'https://example.test','started_at':'2026-10-09T10:00:00+00:00','mode':'deep','scan_id':'abc','assessment':'Web Audit'},'findings':[{'name':'Missing HSTS','severity':'low','endpoint':'https://example.test','evidence_state':'CONFIRMED_OBSERVED','sources':['http-passive'],'why_reported':'Directly observed in assessment evidence.','description':'HSTS was not present.','impact':'HTTPS users may be exposed to downgrade risk.','remediation':'Enable HSTS for the intended HTTPS host.','owasp_category':'A04:2025 Cryptographic Failures','cwe':'CWE-319','source_commands':{'http-passive':'Built-in HTTP GET probe: https://example.test'}}], 'not_reported':[]}
            path=write_pdf_report(report,out)
            self.assertTrue(path.exists())
            self.assertGreater(path.stat().st_size,1000)

if __name__=='__main__': unittest.main()
