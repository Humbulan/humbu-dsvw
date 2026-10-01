# DSSW - Damn Small Secure Web

A hardened fork of DSVW, side-by-side with the vulnerable version.

## Comparison

| Attack | DSVW :65412 | DSSW :65413 |
|---|---|---|
| File read via file:// | leaks /etc/passwd | Scheme not allowed |
| XPath injection | returns admin | returns - |
| SQLi auth bypass | Welcome admin | incorrect |
| Reflected XSS | executes | escaped |
| Open redirect | redirects | rejected |
| JSONP XSS | executes | rejected |
| Header injection | injects | falls back to utf8 |
| Memory DoS | OOM | capped at 1000 |

## The 12 fixes

1. SQL injection in id - parameterized query (?)
2. Reflected XSS in v - html.escape on replacement
3. Path traversal in path - reject URI schemes, realpath, trailing separator
4. DNS injection in domain - strict hostname regex
5. XXE in xml - XMLParser(load_dtd=False, resolve_entities=False, no_network=True)
6. XPath injection in name - variable binding ($n)

7. Memory DoS in size - cap at 1000
8. SQL injection in comment - parameterized INSERT
9. Open redirect in redir - same-origin only, reject //
10. JSONP XSS in users.json - callback identifier regex
11. SQL injection in login - parameterized SELECT
12. Header injection in charset - whitelist

## Reproduction

Terminal 1:
cd ~/DSVW && python3 dsvw.py

Terminal 2:
cd ~/DSVW && python3 dssw.py

Test:
curl -s "http://127.0.0.1:65412/?path=file:///etc/passwd"   # leaks
curl -s "http://127.0.0.1:65413/?path=file:///etc/passwd"   # Scheme not allowed

## Credits

Original DSVW by Miroslav Stampar (github.com/stamparm/DSVW).
License: Unlicense (public domain) - inherited from DSVW.
