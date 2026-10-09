import asyncio
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from reconforge.audit.crawler import WebCrawler, audit_response
from reconforge.cli import build_parser, make_context

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        path=urlparse(self.path).path
        query=urlparse(self.path).query
        self.send_response(200)
        if path == '/':
            self.send_header('Content-Type','text/html')
            self.send_header('Set-Cookie','sid=abc; Path=/')
            self.end_headers()
            self.wfile.write(b'''<!doctype html><title>Home</title>
                <a href="/login?q=hello">login</a>
                <a href="/dir/">dir</a>
                <a href="/api?next=/home">api</a>
                <script src="/static/app.js"></script>
                <form method="POST" action="/submit"><input type="password" name="password"><input name="name"></form>''')
        elif path == '/login':
            value=query.split('=',1)[1] if '=' in query else ''
            self.send_header('Content-Type','text/html')
            self.end_headers()
            self.wfile.write(f'<html><body>ref={value}</body></html>'.encode())
        elif path == '/dir/':
            self.send_header('Content-Type','text/html')
            self.end_headers()
            self.wfile.write(b'<html><title>Index of /dir/</title><body>Index of /dir/</body></html>')
        elif path == '/api':
            self.send_header('Content-Type','application/json')
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
        elif path == '/static/app.js':
            self.send_header('Content-Type','application/javascript')
            self.end_headers()
            self.wfile.write(b'fetch("/api")')
        elif path == '/submit':
            self.send_header('Content-Type','text/html')
            self.end_headers()
            self.wfile.write(b'ok')
        else:
            self.send_header('Content-Type','text/plain')
            self.end_headers()
            self.wfile.write(b'ok')

class WebAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        import threading
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()
    def _ctx(self, root):
        p=build_parser(); args=p.parse_args([self.base,'--authorized','--audit-only','--crawl-pages','10','--crawl-depth','2','--crawl-rate','20','--crawl-concurrency','2','--output-dir',str(root)])
        return make_context(args)
    def test_audit_rules_safe_candidate_states(self):
        findings=audit_response(
            url=self.base+'/', status=200, headers={'Content-Type':'text/html'}, cookies=['sid=abc; Path=/'],
            body='<form method="POST"><input type="password" name="p"></form>',
            forms=[{'action':self.base+'/submit','method':'POST','inputs':[{'name':'password','type':'password'}]}],
            discovered_urls=[], title='Home'
        )
        names={f['name']:f for f in findings}
        self.assertIn('Missing clickjacking protection',names)
        self.assertEqual(names['State-changing form may lack CSRF protection']['evidence_state'],'NEEDS_VALIDATION')
        self.assertEqual(names['Cookie sid missing security flags']['evidence_state'],'CONFIRMED_OBSERVED')
    def test_crawler_discovers_forms_and_pages(self):
        with tempfile.TemporaryDirectory() as t:
            ctx=self._ctx(Path(t))
            result=asyncio.run(WebCrawler(ctx).run())
            crawl=result.summary['crawl']
            urls={p['url'] for p in crawl['pages']}
            self.assertIn(self.base+'/',urls)
            self.assertIn(self.base+'/login?q=hello',urls)
            self.assertIn(self.base+'/dir/',urls)
            self.assertGreaterEqual(len(crawl['forms']),1)
            audit_names={f['name'] for f in crawl['findings']}
            self.assertIn('Directory listing exposed',audit_names)
            self.assertIn('State-changing form may lack CSRF protection',audit_names)
            self.assertFalse(any(p.get('url','').endswith('/submit') for p in crawl['pages']))

if __name__=='__main__': unittest.main()
