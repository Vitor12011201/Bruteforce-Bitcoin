"""Browser checks against the running local UI; no transactions or exported keys."""

import json
import os
import sys
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from bip39_lab.wallet import Network, derive_wallet, mnemonic_from_entropy


URL = os.environ.get("BIP39_LAB_QA_URL", "http://127.0.0.1:8765")
ARTIFACTS = ROOT / ".qa"
VIEWPORTS = [(1920, 1080), (1366, 768), (1024, 768), (768, 1024), (390, 844), (360, 800), (320, 700)]


def check_browser(browser_type, *, full_matrix: bool) -> dict:
    browser = browser_type.launch(headless=True)
    page = browser.new_page(viewport={"width": 1366, "height": 768}, reduced_motion="reduce")
    runtime_errors = []
    page.on("pageerror", lambda error: runtime_errors.append(str(error)))
    response = page.goto(URL)
    assert response.status == 200
    expect(page.locator("#connection-text")).to_have_text("Painel local conectado")
    page.locator("#clear").click()
    page.locator("#example").click()
    expect(page.locator("#target")).to_have_value("bcrt1q8rs36kt3ugjkkwpj52kq07v76xddlhm0u0hurw")
    page.locator("#mode").select_option("visual")
    page.locator("#start").click()
    expect(page.locator("#run-state")).to_have_text("Experimento em andamento")
    expect(page.locator("#attempts")).not_to_have_text("0")
    expect(page.locator("#balance-status")).to_have_text("NÓ CONECTADO")
    expect(page.locator("#balance-amount")).to_have_text("0,00000000")
    for width, height in VIEWPORTS if full_matrix else [(1366, 768), (390, 844)]:
        page.set_viewport_size({"width": width, "height": height})
        page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), f"Overflow at {width}"
        assert page.locator(".word-slot").count() == 12
        if full_matrix:
            page.screenshot(path=str(ARTIFACTS / f"live-{width}.png"), full_page=True)
    page.locator("#stop").click()
    expect(page.locator("#run-state")).to_have_text("Experimento interrompido")
    page.set_viewport_size({"width": 1366, "height": 768})
    page.locator("#mode").select_option("fast")
    page.locator("#start").click()
    expect(page.locator("#run-state")).to_have_text("Alvo encontrado", timeout=15000)
    expect(page.locator("#result-description")).to_contain_text("é zero", timeout=10000)
    expect(page.locator("#result")).not_to_have_class("result-panel funded")
    page.locator("#reveal").click()
    expect(page.locator("#key-dialog")).to_be_visible()
    expected_key = derive_wallet(mnemonic_from_entropy((127).to_bytes(16, "big")), Network.REGTEST).private_key.hex()
    assert page.locator("#private-key").inner_text() == expected_key
    page.locator("#hide-key").click()
    expect(page.locator("#key-dialog")).not_to_be_visible()
    expect(page.locator("#private-key")).to_have_text("")
    # The full-phrase operation validates exactly one user-supplied mnemonic;
    # it must not enumerate the 12-word search space.
    page.locator("#operation").select_option("validate")
    full_phrase = mnemonic_from_entropy((127).to_bytes(16, "big"))
    page.locator("#template").fill(full_phrase)
    expect(page.locator("#total")).to_have_text("1")
    page.locator("#start").click()
    expect(page.locator("#run-state")).to_have_text("Alvo encontrado", timeout=10000)
    expect(page.locator("#attempts")).to_have_text("1")
    expect(page.locator("#total")).to_have_text("1")
    page.locator("#operation").select_option("limited")
    page.locator("#template").fill("abandon ? ? ? ? ? ? ? ? ? ? ?")
    expect(page.locator("#total")).to_have_text("2.658.455.991.569.831.745.807.614.120.560.689.152")
    giant_total = 2_658_455_991_569_831_745_807_614_120_560_689_152
    giant_attempts = 9_007_199_254_740_992
    giant_remaining = giant_total - giant_attempts
    giant_progress_scaled = giant_attempts * 1_000_000 // giant_total
    giant_eta_tenths = (giant_remaining * 10 + 3600 // 2) // 3600
    expected_giant_eta = f"{giant_eta_tenths // 10:,}".replace(",", ".") + f",{giant_eta_tenths % 10} h"
    giant_metrics = page.evaluate(f"""() => {{
        const stats = {{
          total_combinations: "{giant_total}",
          attempts: "{giant_attempts}",
          remaining_combinations: "{giant_remaining}",
          rate: 1
        }};
        const scaled = progressScaled(stats);
        return {{percentage: formatScaledInteger(scaled, 4), eta: etaDuration(stats), type: typeof scaled}};
      }}""")
    assert giant_metrics == {
        "percentage": f"{giant_progress_scaled // 10_000},{giant_progress_scaled % 10_000:04d}",
        "eta": expected_giant_eta,
        "type": "bigint",
    }
    if full_matrix:
        page.screenshot(path=str(ARTIFACTS / "matched-zero.png"), full_page=True)
        def funded_fixture(route):
            response = route.fetch()
            data = response.json()
            data["funded_alert"] = True
            data["balance"].update(status="verified", satoshis=12_500_001, after_match=True)
            route.fulfill(response=response, json=data)

        page.route("**/api/state", funded_fixture)
        expect(page.locator("#result-title")).to_have_text("Alvo encontrado com saldo de teste")
        expect(page.locator("#balance-amount")).to_have_text("0,12500001")
        expect(page.locator("#result")).to_have_class("result-panel funded")
        expect(page.locator("#result-label")).to_contain_text("SALDO CONFIRMADOS")
        page.screenshot(path=str(ARTIFACTS / "funded-alert-SIMULATED.png"), full_page=True)
        page.unroute("**/api/state", funded_fixture)
        expect(page.locator("#balance-amount")).to_have_text("0,00000000")
        expect(page.locator("#result-title")).to_have_text("Correspondência exata encontrada")
    page.locator("#generate").click()
    expect(page.locator("#generated-dialog")).to_be_visible()
    assert len(page.locator("#generated-phrase").inner_text().split()) == 12
    page.locator("#use-generated").click()
    expect(page.locator("#generated-phrase")).to_have_text("")
    page.locator("#target").fill("invalid")
    page.locator("#start").click()
    expect(page.locator("#page-error")).to_be_visible()
    page.locator("#clear").click()
    expect(page.locator("#page-error")).not_to_be_visible()
    assert page.evaluate("localStorage.length + sessionStorage.length") == 0
    assert not runtime_errors, runtime_errors
    browser.close()
    return {"browser": browser_type.name, "viewports": VIEWPORTS if full_matrix else [(1366, 768), (390, 844)], "runtime_errors": runtime_errors, "result": "passed"}


if __name__ == "__main__":
    ARTIFACTS.mkdir(exist_ok=True)
    with sync_playwright() as playwright:
        results = [check_browser(playwright.chromium, full_matrix=True), check_browser(playwright.firefox, full_matrix=False)]
    print(json.dumps(results, ensure_ascii=False))
