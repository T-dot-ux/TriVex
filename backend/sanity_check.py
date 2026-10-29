from trivex_detector import analyze_url

tests = [
    ('http://192.168.1.1/secure/login',        'phishing'),
    ('http://paypal-verify-account.com/update', 'phishing'),
    ('https://www.google.com',                  'benign'),
    ('https://github.com',                      'benign'),
    ('http://secure.login.verify.banking.evil.com/account', 'phishing'),
]

print('=== trivex_detector sanity check ===')
all_ok = True
for url, expected in tests:
    r = analyze_url(url)
    got = r.final_verdict if not r.error else 'ERROR:'+r.error
    ok  = ('phishing' in got) == (expected == 'phishing')
    mark = 'OK' if ok else 'FAIL'
    if not ok: all_ok = False
    print(f'  [{mark}] {url[:60]:<60} => {got} (expected {expected})')
print()
print('All tests passed!' if all_ok else 'SOME TESTS FAILED')
