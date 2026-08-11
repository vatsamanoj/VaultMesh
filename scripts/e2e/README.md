# Browser end-to-end test

`roundtrip.py` drives a real Chromium against the chat UI the coordinator serves
and verifies a full **tap-to-restore round-trip**:

1. enroll a vault (new chat),
2. attach + send a file (WebCrypto client-side encrypt → node-agent),
3. **tap the file bubble** to restore it (download → decrypt),
4. assert the downloaded bytes are byte-identical to the upload.

## Run it

```sh
# one-shot: builds + boots coordinator/node-agent, runs the test, tears down
PYTHON=/path/to/venv/python PLAYWRIGHT_CHROME=/path/to/chromium ./run.sh
```

Or against services you already have running:

```sh
VAULT_COORDINATOR_URL=http://127.0.0.1:8787 \
PLAYWRIGHT_CHROME=/path/to/chromium \
  python roundtrip.py
```

## Requirements

- `pip install playwright`
- A Chromium: either `playwright install chromium`, or set `PLAYWRIGHT_CHROME`
  to an existing binary.
- The chat UI must be reached over a **secure context** (`http://127.0.0.1` /
  `localhost` or `https://`) or WebCrypto is unavailable and the upload fails.

Exit code is `0` on PASS, `1` on FAIL.

Both scripts run a **port preflight** first (`lib.sh`): if a required port is
busy they reap stale VaultMesh `coordinator`/`node-agent` processes left by an
earlier run and re-check, and only abort if a port is still held by an unrelated
process — so back-to-back runs don't trip over orphaned servers.

## Files

- `run.sh` — boot + tap-to-restore round-trip (`roundtrip.py`).
- `durability.sh` — 2-node mesh durability drill (shard loss, self-heal,
  peer-assisted repair).
- `lib.sh` — shared port-preflight helpers.
- `roundtrip.py` — the Playwright round-trip test.
