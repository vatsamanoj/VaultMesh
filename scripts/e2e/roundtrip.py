#!/usr/bin/env python3
"""Browser end-to-end round-trip for the VaultMesh chat UI.

Drives a real Chromium against the console served by the coordinator:

  enroll a vault  ->  attach + send a file (client-side encrypted upload)
                  ->  TAP the file bubble to restore it (download + decrypt)
                  ->  assert the downloaded bytes are byte-identical.

This exercises the full data path both ways through the actual UI, including
the WebCrypto encrypt on send and decrypt on tap-to-restore.

Requires: playwright (`pip install playwright`) and a Chromium. Point
PLAYWRIGHT_CHROME at a chromium binary, or run `playwright install chromium`.

Env:
  VAULT_COORDINATOR_URL  default http://127.0.0.1:8787   (serves the chat UI)
  PLAYWRIGHT_CHROME      path to a chromium executable (optional)
  VAULT_TEST_KEY         vault passphrase to use (default 'roundtrip-key')

Exit code 0 on PASS, 1 on FAIL.
"""
import hashlib
import os
import sys
import tempfile

from playwright.sync_api import sync_playwright

CO = os.environ.get("VAULT_COORDINATOR_URL", "http://127.0.0.1:8787")
KEY = os.environ.get("VAULT_TEST_KEY", "roundtrip-key")
CHROME = os.environ.get("PLAYWRIGHT_CHROME")
NAME = "secret-notes.txt"


def main():
    work = tempfile.mkdtemp(prefix="vm-e2e-")
    src = os.path.join(work, NAME)
    data = os.urandom(200000)
    with open(src, "wb") as f:
        f.write(data)
    want = hashlib.sha256(data).hexdigest()

    with sync_playwright() as p:
        launch = {"args": ["--no-sandbox"]}
        if CHROME:
            launch["executable_path"] = CHROME
        browser = p.chromium.launch(**launch)
        ctx = browser.new_context(accept_downloads=True, viewport={"width": 1100, "height": 800})
        pg = ctx.new_page()
        pg.on("dialog", lambda d: d.accept(KEY))  # answer the vault-key prompt

        pg.goto(CO + "/", wait_until="networkidle")
        pg.wait_for_timeout(400)

        # 1. enroll a vault (new chat)
        pg.click("#newBtn")
        pg.fill("#mLabel", "roundtrip")
        pg.click("#mOk")
        pg.wait_for_selector(".sysmsg", timeout=8000)

        # 2. attach + send the file (client-side encrypted upload)
        pg.set_input_files("#fileInput", src)
        pg.wait_for_selector(".stage .chip")
        pg.click("#sendBtn")
        pg.wait_for_function(
            "document.querySelector('.msg.out') && !document.querySelector('.tick.pending')",
            timeout=20000,
        )
        pg.wait_for_timeout(400)

        # 3. TAP the file bubble -> restore -> browser download
        with pg.expect_download(timeout=20000) as dl_info:
            pg.click(".msg.out .filecard")
        dl = dl_info.value
        out = os.path.join(work, "restored.bin")
        dl.save_as(out)
        with open(out, "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        filename = dl.suggested_filename
        browser.close()

    print(f"uploaded  sha256={want}")
    print(f"restored  sha256={got}  filename='{filename}'")
    if got == want and filename == NAME:
        print("PASS  tap-to-restore round-trip is byte-identical")
        return 0
    print("FAIL  mismatch (bytes or filename)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
