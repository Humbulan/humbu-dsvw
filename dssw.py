#!/usr/bin/env python3
import html, http.client, http.server, io, json, os, random, re, socket, socketserver, sqlite3, string, subprocess, sys, time, traceback, urllib.parse, xml.etree.ElementTree  # Python 3 required

try:
    import lxml.etree
except ImportError:
    print("[!] please install 'python-lxml' for XPath support\n")

NAME = "Damn Small Secure Web (DSSW)"
VERSION = "1.0"
GITHUB = "https://github.com/stamparm/DSVW"
AUTHOR = "hardened fork of Miroslav Stampar's DSVW"
LISTEN_ADDRESS, LISTEN_PORT = "127.0.0.1", 65413

HTML_PREFIX = "<!DOCTYPE html>\n<html>\n<head>\n<style>a {font-weight: bold; text-decoration: none; visited: blue; color: blue;} table {border-collapse: collapse; margin: 12px; border: 2px solid black} th, td {border: 1px solid black; padding: 3px} span {font-size: larger; font-weight: bold}</style>\n<title>%s</title>\n</head>\n<body style='font: 12px monospace'>\n" % html.escape(NAME)

HTML_POSTFIX = "<div style=\"position: fixed; bottom: 5px; text-align: center; width: 100%%;\">Powered by <a href=\"%s\" style=\"font-weight: bold; text-decoration: none\">DSVW</a> (v<b>%s</b>) - DSSW hardened fork</div>\n</body>\n</html>" % (GITHUB, VERSION)

USERS_XML = """<?xml version="1.0" encoding="utf-8"?><users><user id="0"><username>admin</username><name>admin</name><surname>admin</surname><password>7en8aiDoh!</password></user><user id="1"><username>dricci</username><name>dian</name><surname>ricci</surname><password>12345</password></user><user id="2"><username>amason</username><name>anthony</name><surname>mason</surname><password>gandalf</password></user><user id="3"><username>svargas</username><name>sandra</name><surname>vargas</surname><password>phest1945</password></user></users>"""

BASE_DIR = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
ALLOWED_CHARSETS = ("utf8", "utf-8", "iso-8859-1", "ascii")
CALLBACK_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]*$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")


def init():
    global connection
    http.server.HTTPServer.allow_reuse_address = True
    connection = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, name TEXT, surname TEXT, password TEXT)")
    cursor.executemany("INSERT INTO users(id, username, name, surname, password) VALUES(NULL, ?, ?, ?, ?)",
                       ((_.findtext("username"), _.findtext("name"), _.findtext("surname"), _.findtext("password"))
                        for _ in xml.etree.ElementTree.fromstring(USERS_XML).findall("user")))
    cursor.execute("CREATE TABLE comments(id INTEGER PRIMARY KEY AUTOINCREMENT, comment TEXT, time TEXT)")


def esc(value):
    return "-" if value is None else html.escape(str(value))


class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
        code, content, params, cursor = http.client.OK, HTML_PREFIX, dict(
            (match.group("parameter"),
             urllib.parse.unquote(','.join(re.findall(r"(?:\A|[?&])%s=([^&]+)" % match.group("parameter"), query))))
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)([^&]+)", query)), connection.cursor()
        try:
            if path == '/':
                if "id" in params:
                    # FIX 1: parameterized query (was already fixed in the fork we forked)
                    cursor.execute("SELECT id, username, name, surname FROM users WHERE id=?", (params["id"],))
                    content += "<div><span>Result(s):</span></div><table><thead><th>id</th><th>username</th><th>name</th><th>surname</th></thead>%s</table>%s" % (
                        "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % esc(_) for _ in row)
                                for row in cursor.fetchall()), HTML_POSTFIX)
                elif "v" in params:
                    # FIX 2: escape reflected value (was XSS)
                    content += re.sub(r"(v<b>)[^<]+(</b>)", r"\g<1>%s\g<2>" % html.escape(params["v"]), HTML_POSTFIX)
                elif "object" in params:
                    content = "Pickle deserialization is disabled."
                elif "path" in params:
                    # FIX 3: reject ALL URI schemes + realpath + trailing separator
                    p = params["path"]
                    if "://" in p or p.lower().startswith("file:") or p.startswith("\\\\"):
                        content = "Scheme not allowed."
                    else:
                        safe_path = os.path.realpath(os.path.join(BASE_DIR, p))
                        if safe_path != BASE_DIR and not safe_path.startswith(BASE_DIR + os.sep):
                            content = "Access denied."
                        else:
                            content = open(safe_path, "rb").read().decode()
                elif "domain" in params:
                    # FIX 4: strict hostname validation (was DNS-based injection vector)
                    if not DOMAIN_RE.match(params["domain"]) or len(params["domain"]) > 253:
                        content = "Invalid domain."
                    else:
                        content = subprocess.run(["nslookup", params["domain"]], capture_output=True, text=True).stdout
                elif "xml" in params:
                    # FIX 5: safe parser (XXE disabled)
                    try:
                        parser = lxml.etree.XMLParser(load_dtd=False, resolve_entities=False, no_network=True)
                        content = lxml.etree.tostring(lxml.etree.parse(io.BytesIO(params["xml"].encode()), parser), pretty_print=True).decode()
                    except Exception as e:
                        content = "XML parsing error: %s" % html.escape(str(e))
                elif "name" in params:
                    # FIX 6: parameterized XPath via lxml variable binding
                    try:
                        root = lxml.etree.parse(io.BytesIO(USERS_XML.encode()))
                        found = root.xpath(".//user[name/text()=$n]", n=params["name"])
                        content += "<b>Surname:</b> %s%s" % (esc(found[-1].find("surname").text if found else "-"), HTML_POSTFIX)
                    except Exception as e:
                        content += "XPath error: %s%s" % (html.escape(str(e)), HTML_POSTFIX)
                elif "size" in params:
                    # FIX 7: cap size to prevent memory DoS
                    try:
                        n = max(0, min(int(params["size"]), 1000))
                    except (ValueError, TypeError):
                        n = 32
                    start = time.time()
                    _ = "<br>".join("#" * n for _ in range(n))
                    content += "<b>Time required</b> (to 'resize image' to %dx%d): %.6f seconds%s" % (n, n, time.time() - start, HTML_POSTFIX)
                elif "comment" in params or query == "comment=":
                    if "comment" in params:
                        # FIX 8: parameterized INSERT
                        cursor.execute("INSERT INTO comments VALUES(NULL, ?, ?)", (params["comment"], time.ctime()))
                        content += "Thank you for leaving the comment. Please click <a href=\"/?comment=\">here</a> to see all comments%s" % HTML_POSTFIX
                    else:
                        cursor.execute("SELECT id, comment, time FROM comments")
                        content += "<div><span>Comment(s):</span></div><table><thead><th>id</th><th>comment</th><th>time</th></thead>%s</table>%s" % (
                            "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % esc(_) for _ in row)
                                    for row in cursor.fetchall()), HTML_POSTFIX)
                elif "include" in params:
                    content = "Remote code inclusion is disabled."
                elif "redir" in params:
                    # FIX 9: same-origin relative redirects only (was open redirect)
                    redir = params["redir"]
                    if redir.startswith("/") and not redir.startswith("//"):
                        content = content.replace("<head>", "<head><meta http-equiv=\"refresh\" content=\"0; url=%s\"/>" % html.escape(redir))
                    else:
                        content += "Invalid redirect target.%s" % HTML_POSTFIX
                else:
                    content += ("<div><span>DSSW endpoints:</span></div><ul>"
                                "<li><a href=\"/?id=1\">?id=1</a> (parameterized)</li>"
                                "<li><a href=\"/?name=admin\">?name=admin</a> (XPath param)</li>"
                                "<li><a href=\"/?comment=\">?comment=</a> (parameterized)</li>"
                                "<li><a href=\"/users.json\">/users.json</a></li>"
                                "<li><a href=\"/login?username=admin&amp;password=7en8aiDoh!\">/login</a> (parameterized)</li>"
                                "</ul>%s" % HTML_POSTFIX)
            elif path == "/users.json":
                # FIX 10: JSONP callback identifier validation
                callback = params.get("callback", "")
                if callback and not CALLBACK_RE.match(callback):
                    callback = ""
                data = json.dumps(dict((_.findtext("username"), _.findtext("surname"))
                                       for _ in xml.etree.ElementTree.fromstring(USERS_XML).findall("user")))
                content = "%s%s%s" % ("%s(" % callback if callback else "", data, ")" if callback else "")
            elif path == "/login":
                # FIX 11: parameterized SELECT (was string concat on password)
                cursor.execute("SELECT * FROM users WHERE username=? AND password=?",
                               (params.get("username", ""), params.get("password", "")))
                if cursor.fetchall():
                    session_id = "".join(random.sample(string.ascii_letters + string.digits, 20))
                    content += ("Welcome <b>%s</b>"
                                "<meta http-equiv=\"Set-Cookie\" content=\"SESSIONID=%s; path=/; HttpOnly; SameSite=Strict\">"
                                "<meta http-equiv=\"refresh\" content=\"1; url=/\"/>") % (
                        html.escape(params.get("username", "")), session_id)
                else:
                    content += ("The username and/or password is incorrect"
                                "<meta http-equiv=\"Set-Cookie\" content=\"SESSIONID=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT\">")
            else:
                code = http.client.NOT_FOUND
        except Exception:
            content = traceback.format_exc()
            code = http.client.INTERNAL_SERVER_ERROR
        finally:
            self.send_response(code)
            self.send_header("Connection", "close")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.send_header("Referrer-Policy", "no-referrer")
            # FIX 12: charset whitelist (was header injection vector)
            charset = params.get("charset", "utf8")
            if charset not in ALLOWED_CHARSETS:
                charset = "utf8"
            self.send_header("Content-Type", "%s; charset=%s" % (
                "text/html" if content.startswith("<!DOCTYPE html>") else "text/plain", charset))
            self.end_headers()
            self.wfile.write(("%s%s" % (content, HTML_POSTFIX if HTML_PREFIX in content and "DSSW hardened fork" not in content else "")).encode())
            self.wfile.flush()


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        http.server.HTTPServer.server_bind(self)


if __name__ == "__main__":
    init()
    print("%s #v%s\n by: %s\n\n[i] running HTTP server at 'http://%s:%d'..." % (NAME, VERSION, AUTHOR, LISTEN_ADDRESS, LISTEN_PORT))
    try:
        ThreadingServer((LISTEN_ADDRESS, LISTEN_PORT), ReqHandler).serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception as ex:
        print("[x] exception occurred ('%s')" % ex)
    finally:
        os._exit(0)
