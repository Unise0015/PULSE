# Regression checks

Use Python 3.11 or newer in a virtual environment:

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
pulse --help
```

The tracked tests block live socket connections and use temporary SQLite databases and synthetic HTTP responses. No provider keys or real scan targets are needed.

Coverage includes:

- OSV failures, malformed batches, cache recovery, chunk alignment, and offline cache misses.
- NVD, EPSS, and KEV outage warnings without discarding existing findings.
- Scan warnings through project/package scans, history, terminal output, and all four export formats.
- Website headers, bounded downloads, repeated scans, malformed URLs, and incomplete correlation.
- Distinct Angular and AngularJS identities and shared package aliases.
- HTML escaping and rejection of executable reference URLs.

CI runs the suite on Python 3.11 and 3.13 and checks the installed CLI and report template loading outside the checkout. Keep tests in version control; ignore test caches, not the suite.

These checks protect the exercised behavior. They do not measure detection accuracy across arbitrary websites or establish live provider availability.
