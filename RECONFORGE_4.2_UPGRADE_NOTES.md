# ReconForge 4.2.0 Upgrade Notes

This release keeps ReconForge as the single project and strengthens the existing architecture rather than introducing a second agent.

## What changed

1. Target normalization now accepts:
   - `https://host/path`
   - `https://host:8443/path`
   - `host`
   - `192.0.2.10`
   - `192.0.2.10:8080`
   - IPv6 URL / host forms supported by Python's URL parser

2. Explicit custom ports from URLs / `host:port` targets are carried into Nmap when no manual port set is supplied.

3. The HTTP probe produces first-class evidence for high-signal response properties and routes it through the same normalizer, correlation, quality gate, and report pipeline.

4. HTTPS certificate verification failures are retained as evidence and a read-only unverified fallback can collect response headers/body metadata for analysis.

5. Adaptive SQLMap actions preserve the complete parameterized URL and are dispatched through the existing bounded SQLMap adapter.

6. Recon and web stages now use the existing bounded-concurrency scheduler instead of forcing each worker to run one-at-a-time.

7. Missing fuzzing dependencies / wordlists are reported as `skipped` rather than being surfaced as scanner command failures.

8. Each run gets `evidence/manifest.json` with SHA-256 hashes for evidence-relevant run files, excluding mutable reports/state/manifest metadata.

## Recommended workflow

```bash
python3 -m reconforge https://AUTHORIZED-TARGET --authorized --mode deep --dry-run
python3 -m reconforge https://AUTHORIZED-TARGET --authorized --mode deep
```

For a custom port:

```bash
python3 -m reconforge 192.0.2.10:8080 --authorized --mode basic
```

For a scoped assessment:

```bash
python3 -m reconforge app.example.test --authorized --scope scope.example.txt --mode deep
```

The release continues to use the explicit authorization flag and scope enforcement. Use it only on systems you own or are explicitly authorized to assess.
