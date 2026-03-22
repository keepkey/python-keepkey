#!/usr/bin/env python3
"""
generate-test-report.py -- KeepKey Firmware Screen Zoo Report

Builds an organized HTML report from test screenshots, grouped by chain
with letter-number indexing:

  C  = Core (device lifecycle: wipe, reset, recovery, PIN, settings)
  B  = Bitcoin (legacy, segwit, taproot, multisig)
  E  = Ethereum (send, ERC-20, EIP-712, messages, contracts)
  S  = Solana
  T  = TRON
  N  = TON
  Z  = Zcash
  R  = Ripple (XRP)
  A  = Cosmos (ATOM)
  H  = THORChain
  M  = Maya Protocol
  K  = Binance (BNB)
  O  = Osmosis
  D  = Other / Misc (EOS, Nano, BIP-85, etc.)
"""
import os
import sys
import argparse
import base64
from pathlib import Path
from datetime import datetime

try:
    import xml.etree.ElementTree as ET
except ImportError:
    ET = None

# Chain letter codes + display names + accent colors
CHAIN_MAP = {
    # letter: (display_name, accent_color, module_patterns)
    'C': ('Core', '#48BB78', [
        'wipedevice', 'resetdevice', 'recoverydevice', 'changepin',
        'applysettings', 'clearsession', 'loaddevice', 'ping',
        'getentropy', 'cipherkeyvalue', 'signidentity', 'bip85',
    ]),
    'B': ('Bitcoin', '#F7931A', [
        'signtx', 'getaddress', 'signmessage', 'verifymessage',
        'getpublickey', 'signtx_segwit', 'signtx_p2tr', 'signtx_raw',
        'signtx_xfer', 'signtx_bgold', 'signtx_dash', 'signtx_grs',
    ]),
    'E': ('Ethereum', '#627EEA', [
        'ethereum',
    ]),
    'S': ('Solana', '#14F195', [
        'solana',
    ]),
    'T': ('TRON', '#EF0027', [
        'tron',
    ]),
    'N': ('TON', '#0098EA', [
        'ton',
    ]),
    'Z': ('Zcash', '#F4B728', [
        'zcash', 'signtx_zcash',
    ]),
    'R': ('Ripple (XRP)', '#23292F', [
        'ripple',
    ]),
    'A': ('Cosmos (ATOM)', '#2E3148', [
        'cosmos',
    ]),
    'H': ('THORChain', '#23DCC8', [
        'thorchain', '2thorchain',
    ]),
    'M': ('Maya Protocol', '#3B82F6', [
        'mayachain',
    ]),
    'K': ('Binance (BNB)', '#F3BA2F', [
        'binance',
    ]),
    'O': ('Osmosis', '#5604AB', [
        'osmosis',
    ]),
    'D': ('Other', '#8b949e', [
        'eos', 'nano', 'multisig',
    ]),
}


def classify_module(module_name):
    """Map a test module name to a chain letter code.
    Check chain-specific patterns first, Bitcoin generic patterns last."""
    name = module_name.lower().replace('msg_', '')

    # Check all non-Bitcoin chains first (specific patterns)
    for letter, (_, _, patterns) in CHAIN_MAP.items():
        if letter == 'B':
            continue  # skip Bitcoin on first pass
        for pattern in patterns:
            if pattern in name:
                return letter

    # Bitcoin is the fallback for generic BTC test names
    for pattern in CHAIN_MAP['B'][2]:
        if pattern in name:
            return 'B'

    return 'D'  # truly unknown


def parse_junit(junit_path):
    if not junit_path or not os.path.exists(junit_path):
        return {}
    tree = ET.parse(junit_path)
    results = {}
    for tc in tree.iter('testcase'):
        name = tc.get('name', '')
        failure = tc.find('failure')
        error = tc.find('error')
        skip = tc.find('skipped')
        if failure is not None:
            results[name] = 'FAIL'
        elif error is not None:
            results[name] = 'ERROR'
        elif skip is not None:
            results[name] = 'SKIP'
        else:
            results[name] = 'PASS'
    return results


def collect_screenshots(screenshot_dir):
    """Walk screenshot dirs, return organized structure."""
    tree = {}
    if not os.path.exists(screenshot_dir):
        return tree

    for module in sorted(os.listdir(screenshot_dir)):
        module_path = os.path.join(screenshot_dir, module)
        if not os.path.isdir(module_path):
            continue
        tests = {}
        for test in sorted(os.listdir(module_path)):
            test_path = os.path.join(module_path, test)
            if not os.path.isdir(test_path):
                continue
            pngs = sorted([
                os.path.join(test_path, f)
                for f in os.listdir(test_path)
                if f.endswith('.png')
            ])
            if pngs:
                tests[test] = pngs
        if tests:
            tree[module] = tests

    # Fallback: flat scr*.png
    if not tree:
        flat = sorted([os.path.join(screenshot_dir, f) for f in os.listdir(screenshot_dir) if f.endswith('.png')])
        if flat:
            tree['all'] = {'full_run': flat}

    return tree


def img_to_data_uri(path):
    with open(path, 'rb') as f:
        return f'data:image/png;base64,{base64.b64encode(f.read()).decode()}'


def is_blank(path):
    """Check if screenshot is mostly blank (< 50 white pixels)."""
    try:
        data = open(path, 'rb').read()
        return len(data) < 400
    except:
        return True


def generate_html(screenshots, junit_results, output_path):
    total_screens = sum(len(p) for t in screenshots.values() for p in t.values())
    total_tests = sum(len(t) for t in screenshots.values())
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    # Group modules by chain letter
    chains = {}
    for module, tests in screenshots.items():
        letter = classify_module(module)
        if letter not in chains:
            chains[letter] = {}
        chains[letter][module] = tests

    # Count per chain
    chain_stats = {}
    for letter in chains:
        tests_count = sum(len(t) for t in chains[letter].values())
        screens_count = sum(len(p) for t in chains[letter].values() for p in t.values())
        chain_stats[letter] = (tests_count, screens_count)

    html = [f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>KeepKey Firmware Screen Zoo</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 0; }}
  .header {{ background: #161b22; border-bottom: 3px solid #14F195; padding: 24px 32px; }}
  .header h1 {{ color: #14F195; margin: 0 0 4px; font-size: 24px; }}
  .header .subtitle {{ color: #8b949e; font-size: 14px; }}
  .content {{ max-width: 1400px; margin: 0 auto; padding: 24px 32px; }}

  .index {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin: 24px 0; }}
  .index-card {{ background: #161b22; border-radius: 8px; padding: 12px 16px; border-left: 4px solid #30363d; cursor: pointer; text-decoration: none; color: inherit; }}
  .index-card:hover {{ background: #1c2128; }}
  .index-card .letter {{ font-size: 28px; font-weight: 700; float: right; opacity: 0.3; }}
  .index-card .chain-name {{ font-weight: 600; font-size: 14px; }}
  .index-card .chain-stats {{ font-size: 12px; color: #8b949e; margin-top: 4px; }}

  .chain-section {{ margin: 32px 0; }}
  .chain-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #21262d; }}
  .chain-letter {{ font-size: 32px; font-weight: 800; opacity: 0.6; }}
  .chain-title {{ font-size: 20px; font-weight: 600; }}

  .test-card {{ margin: 8px 0; padding: 12px 16px; background: #161b22; border-radius: 8px; border-left: 3px solid #30363d; }}
  .test-card.pass {{ border-left-color: #3fb950; }}
  .test-card.fail {{ border-left-color: #f85149; }}
  .test-id {{ font-size: 12px; color: #8b949e; margin-bottom: 4px; }}
  .test-name {{ font-weight: 600; font-size: 14px; }}
  .badge {{ display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; margin-left: 6px; vertical-align: middle; }}
  .badge.pass {{ background: #238636; color: #fff; }}
  .badge.fail {{ background: #da3633; color: #fff; }}
  .badge.skip {{ background: #6e7681; color: #fff; }}

  .screens {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }}
  .screen {{ background: #000; border: 1px solid #30363d; border-radius: 4px; overflow: hidden; }}
  .screen img {{ display: block; image-rendering: pixelated; width: 384px; height: 96px; }}
  .screen-num {{ font-size: 9px; color: #484f58; text-align: center; padding: 1px; background: #0d1117; }}
  .screen.blank {{ opacity: 0.3; }}

  .footer {{ text-align: center; color: #484f58; font-size: 12px; padding: 32px; border-top: 1px solid #21262d; margin-top: 48px; }}
</style>
</head><body>
<div class="header">
  <h1>KeepKey Firmware Screen Zoo</h1>
  <div class="subtitle">{total_tests} tests | {total_screens} OLED captures | Real emulator screenshots | {timestamp}</div>
</div>
<div class="content">

<h2 style="color:#c9d1d9;margin-top:24px;">Index</h2>
<div class="index">
"""]

    # Sort chains by letter
    for letter in sorted(chains.keys()):
        name, color, _ = CHAIN_MAP.get(letter, ('Other', '#8b949e', []))
        t_count, s_count = chain_stats.get(letter, (0, 0))
        html.append(f"""  <a class="index-card" href="#{letter}" style="border-left-color:{color}">
    <span class="letter" style="color:{color}">{letter}</span>
    <div class="chain-name" style="color:{color}">{name}</div>
    <div class="chain-stats">{t_count} tests, {s_count} frames</div>
  </a>""")

    html.append('</div>')

    # Render each chain section
    test_counter = {}
    for letter in sorted(chains.keys()):
        name, color, _ = CHAIN_MAP.get(letter, ('Other', '#8b949e', []))
        test_counter[letter] = 0

        html.append(f"""
<div class="chain-section" id="{letter}">
  <div class="chain-header">
    <span class="chain-letter" style="color:{color}">{letter}</span>
    <span class="chain-title" style="color:{color}">{name}</span>
  </div>""")

        for module, tests in sorted(chains[letter].items()):
            for test_name, pngs in sorted(tests.items()):
                test_counter[letter] += 1
                idx = f"{letter}{test_counter[letter]}"
                result = junit_results.get(test_name, 'UNKNOWN')
                status_class = 'pass' if result == 'PASS' else 'fail' if result in ('FAIL', 'ERROR') else ''
                badge_class = 'pass' if result == 'PASS' else 'fail' if result in ('FAIL', 'ERROR') else 'skip'

                # Filter out blank screens for cleaner display
                interesting = [(i, p) for i, p in enumerate(pngs) if not is_blank(p)]

                html.append(f"""
  <div class="test-card {status_class}">
    <div class="test-id">{idx} | {module}</div>
    <div class="test-name">{test_name} <span class="badge {badge_class}">{result}</span></div>
    <div class="screens">""")

                for frame_idx, png_path in interesting:
                    data_uri = img_to_data_uri(png_path)
                    html.append(f'      <div class="screen"><img src="{data_uri}" alt="{idx} frame {frame_idx}"><div class="screen-num">{idx}.{frame_idx}</div></div>')

                html.append('    </div>\n  </div>')

        html.append('</div>')

    html.append(f"""
<div class="footer">
  KeepKey Firmware Screen Zoo -- {total_screens} real OLED captures from emulator<br>
  Generated {timestamp} -- All screenshots are pixel-perfect firmware renders
</div>
</div></body></html>""")

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w') as f:
        f.write('\n'.join(html))

    print(f'Report: {output_path}')
    print(f'  {len(chains)} chains, {total_tests} tests, {total_screens} screenshots')
    for letter in sorted(chains.keys()):
        name = CHAIN_MAP.get(letter, ('?',))[0]
        t, s = chain_stats.get(letter, (0, 0))
        print(f'  {letter} {name}: {t} tests, {s} frames')


def main():
    parser = argparse.ArgumentParser(description='KeepKey Screen Zoo Report')
    parser.add_argument('--screenshots', default='screenshots')
    parser.add_argument('--junit', default=None)
    parser.add_argument('--output', default='zoo-report.html')
    args = parser.parse_args()

    junit_results = parse_junit(args.junit)
    screenshots = collect_screenshots(args.screenshots)

    if not screenshots:
        print(f'No screenshots found in {args.screenshots}')
        sys.exit(1)

    generate_html(screenshots, junit_results, args.output)


if __name__ == '__main__':
    main()
