from trivex_detector import analyze_url
import subprocess, json, sys

test_urls = [
    'http://192.168.1.1/secure/login',
    'http://paypal-verify-account.com/update',
    'https://www.google.com',
    'https://en.wikipedia.org/wiki/' + 'a'*70,
    'https://www.e-learning-platform.org/courses',
    'http://test.bank.verify.login.secure.evil.org/auth',
]

print('=== JS / Python Parity Test ===')
all_passed = True
for u in test_urls:
    py_res = analyze_url(u)
    cmd = ['node', '-e', f'const d = require("./frontend/scripts/detector.js"); console.log(JSON.stringify(d.analyzeUrl("{u}")));']
    js_raw = subprocess.check_output(cmd, cwd='..').decode()
    js_res = json.loads(js_raw)

    v_match = py_res.final_verdict == js_res['finalVerdict']
    s_match = py_res.risk_score == js_res['riskScore']
    l_match = py_res.risk_level == js_res['riskLevel']
    ok = v_match and s_match and l_match
    if not ok:
        all_passed = False
    print(f"[{'PASS' if ok else 'FAIL'}] {u[:45]:<45} Py: {py_res.final_verdict}/{py_res.risk_level}/{py_res.risk_score} | JS: {js_res['finalVerdict']}/{js_res['riskLevel']}/{js_res['riskScore']}")

print(f"\nAll parity tests {'PASSED' if all_passed else 'FAILED'}!")
if not all_passed:
    sys.exit(1)
