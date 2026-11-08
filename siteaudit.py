#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

TOOL = "siteaudit/1.2"
CREDIT = "made by exovmiscoding"
UA = TOOL + " (authorized security audit; single target)"
SEVERITIES = ("high", "medium", "low", "info")
SEV_LABEL = {"high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}
SEV_WEIGHT = {"high": 10, "medium": 4, "low": 1, "info": 0}
SEV_COLOR = {
    "high": "\033[1;91m",
    "medium": "\033[1;93m",
    "low": "\033[1;94m",
    "info": "\033[1;90m",
}
RESET = "\033[0m"


class TargetError(Exception):
    pass


@dataclass
class Target:
    scheme: str
    netloc: str
    host: str
    port: int
    path: str

    @property
    def base(self):
        return "%s://%s" % (self.scheme, self.netloc)


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""


@dataclass
class Response:
    status: int
    headers: list = field(default_factory=list)
    body: bytes = b""
    url: str = ""
    error: str = ""

    def header(self, name):
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return ""

    def header_all(self, name):
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def content_type(self):
        return self.header("content-type").lower()


@dataclass
class Result:
    target: str
    started: str
    audit: object
    error: str = ""
    cancelled: bool = False


@dataclass
class InventoryResult:
    started: str
    results: list = field(default_factory=list)
    skipped: list = field(default_factory=list)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, target, timeout, delay, max_requests, insecure, should_stop=None):
        self.target = target
        self.base = target.base
        self.timeout = timeout
        self.delay = max(delay, 0.1)
        self.max_requests = max_requests
        self.insecure = insecure
        self.should_stop = should_stop
        self.count = 0
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ctx)
        )

    @property
    def exhausted(self):
        return self.count >= self.max_requests

    def stopped(self):
        return bool(self.should_stop and self.should_stop())

    def request(self, method, path, extra=None, read_limit=200_000):
        if self.exhausted or self.stopped():
            return None
        if self.count and self.delay:
            time.sleep(self.delay)
        self.count += 1
        url = path if path.startswith(("http://", "https://")) else self.base + path
        headers = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
        if extra:
            headers.update(extra)
        req = urllib.request.Request(url, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return Response(
                    getattr(r, "status", r.getcode()),
                    list(r.headers.items()),
                    r.read(read_limit),
                    url,
                )
        except urllib.error.HTTPError as e:
            try:
                body = e.read(read_limit)
            except Exception:
                body = b""
            return Response(e.code, list(e.headers.items()) if e.headers else [], body, url)
        except urllib.error.URLError as e:
            return Response(0, [], b"", url, str(getattr(e, "reason", e)))
        except (ssl.SSLError, socket.timeout, TimeoutError, ConnectionError, OSError) as e:
            return Response(0, [], b"", url, "%s: %s" % (type(e).__name__, e))


class Audit:
    def __init__(self, client):
        self.client = client
        self.findings = []
        self.passed = []

    def add(self, severity, title, detail, remediation="", evidence=""):
        self.findings.append(Finding(severity, title, detail, evidence, remediation))

    def ok(self, message):
        self.passed.append(message)


def _texty(body, ctype):
    return "html" not in ctype and b"<html" not in body[:300].lower()


def _has(pattern, text_only=True):
    def check(body, ctype):
        if text_only and not _texty(body, ctype):
            return False
        return re.search(pattern, body) is not None

    return check


def _env_file(body, ctype):
    return _texty(body, ctype) and len(
        re.findall(rb"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=", body)
    ) >= 2


def preview(body, limit=170):
    text = body[:600].decode("utf-8", "replace")
    text = "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in text)
    text = re.sub(
        r"(?m)^([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*\S+.*$", r"\1=<redacted>", text
    )
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def parse_cookie(raw):
    parts = raw.split(";")
    attrs = {}
    for p in parts[1:]:
        p = p.strip()
        if not p:
            continue
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip().lower()
        else:
            attrs[p.lower()] = ""
    return parts[0].split("=", 1)[0].strip(), attrs


def check_http_scheme(a, path):
    if a.client.target.scheme == "https":
        return None
    probe = a.client.request("GET", path)
    if probe is None:
        return None
    if probe.status in (301, 302, 303, 307, 308):
        loc = probe.header("location")
        if loc.lower().startswith("https://"):
            a.add(
                "medium",
                "Site answers on plain HTTP before redirecting",
                "The first request can still be read or modified in transit before the "
                "redirect to HTTPS.",
                "Redirect 80 -> 443 at the load balancer and send HSTS on the HTTPS response.",
                "HTTP %d -> %s" % (probe.status, loc),
            )
            a.ok("HTTP redirects to HTTPS")
            return probe
    a.add(
        "high",
        "Site is served over plain HTTP",
        "No HTTPS redirect was observed, so credentials, cookies and page content travel "
        "in clear text.",
        "Serve the site over HTTPS only and redirect all HTTP traffic to it.",
        "HTTP %d" % probe.status if probe.status else (probe.error or "request failed"),
    )
    return probe


def _handshake(host, port, timeout, minv=None, maxv=None, verify=True):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if minv is not None:
        ctx.minimum_version = minv
    if maxv is not None:
        ctx.maximum_version = maxv
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            return ss.version(), ss.getpeercert()


def check_tls(a):
    if a.client.target.scheme != "https":
        return
    host = a.client.target.host
    port = a.client.target.port
    proto = None
    cert = {}
    try:
        proto, cert = _handshake(host, port, a.client.timeout, verify=True)
        a.ok("TLS certificate validates")
    except ssl.SSLCertVerificationError as e:
        a.add(
            "high",
            "Invalid or untrusted TLS certificate",
            "Browsers will warn or refuse the connection. Expired, self-signed or "
            "wrong-hostname certificates break transport security guarantees.",
            "Install a certificate from a trusted CA covering the hostname and renew it "
            "before expiry.",
            getattr(e, "verify_message", None) or str(e),
        )
        try:
            proto, _ = _handshake(host, port, a.client.timeout, verify=False)
        except Exception:
            pass
    except Exception as e:
        a.add(
            "high",
            "TLS handshake failed",
            "Could not establish a TLS session on the given port.",
            "Check that the host serves HTTPS on this port and that the certificate chain "
            "is complete.",
            "%s: %s" % (type(e).__name__, e),
        )
        return

    if proto in ("TLSv1", "TLSv1.1"):
        a.add(
            "high",
            "Deprecated TLS version negotiated (%s)" % proto,
            "TLS 1.0/1.1 are deprecated and vulnerable to known downgrade attacks.",
            "Require TLS 1.2 or newer in the server configuration.",
        )

    for version, label in (
        (ssl.TLSVersion.TLSv1, "TLS 1.0"),
        (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
    ):
        if a.client.stopped():
            break
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                _handshake(host, port, a.client.timeout, minv=version, maxv=version, verify=False)
            a.add(
                "high",
                "%s is still enabled" % label,
                "The server accepts obsolete TLS versions even if it prefers newer ones.",
                "Disable TLS 1.0 and 1.1; allow TLS 1.2 and 1.3 only.",
            )
        except Exception:
            pass

    not_after = (cert or {}).get("notAfter")
    if not_after:
        try:
            expires = ssl.cert_time_to_seconds(not_after)
            days = (expires - time.time()) / 86400.0
            when = datetime.fromtimestamp(expires, timezone.utc).strftime("%Y-%m-%d")
            if days < 0:
                a.add(
                    "high",
                    "TLS certificate has expired",
                    "The certificate expired on %s." % when,
                    "Renew the certificate and automate renewal.",
                    not_after,
                )
            elif days < 14:
                a.add(
                    "medium",
                    "TLS certificate expires soon",
                    "The certificate expires on %s (%d days)." % (when, int(days)),
                    "Renew the certificate now and automate renewal.",
                    not_after,
                )
            else:
                a.ok("TLS certificate valid for %d more days" % int(days))
        except (ValueError, OverflowError):
            pass


def check_headers(a, r):
    https = a.client.target.scheme == "https"
    hsts = r.header("strict-transport-security")
    if https:
        if not hsts:
            a.add(
                "medium",
                "Strict-Transport-Security (HSTS) is not set",
                "Without HSTS, browsers may still reach the site over plain HTTP and are "
                "open to SSL-stripping.",
                "Send Strict-Transport-Security: max-age=31536000; includeSubDomains",
            )
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            max_age = int(m.group(1)) if m else 0
            if max_age < 15552000:
                a.add(
                    "low",
                    "HSTS max-age is short",
                    "max-age=%d is below the recommended six months." % max_age,
                    "Use max-age=31536000 (one year) or longer, and add includeSubDomains.",
                    hsts,
                )
            else:
                a.ok("HSTS enabled with max-age >= 6 months")

    csp = r.header("content-security-policy")
    if not csp:
        a.add(
            "medium",
            "No Content-Security-Policy",
            "CSP is the main defense-in-depth control against cross-site scripting and "
            "third-party script injection.",
            "Add a restrictive Content-Security-Policy (default-src 'self'; object-src "
            "'none'; base-uri 'self'), then tighten with nonces or hashes.",
        )
    elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        a.add(
            "low",
            "CSP allows 'unsafe-inline' or 'unsafe-eval'",
            "These keywords largely defeat the XSS protection CSP is meant to provide.",
            "Replace inline scripts/styles with nonces or hashes and remove 'unsafe-eval'.",
            csp[:160],
        )
    else:
        a.ok("Content-Security-Policy present")

    xfo = r.header("x-frame-options").lower()
    if not xfo and "frame-ancestors" not in csp.lower():
        a.add(
            "medium",
            "No framing protection (clickjacking)",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was returned.",
            "Send X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors 'none'.",
        )
    elif xfo and xfo not in ("deny", "sameorigin"):
        a.add(
            "low",
            "Weak X-Frame-Options value",
            "The returned value '%s' is not a recognized protective value." % xfo,
            "Use X-Frame-Options: DENY or SAMEORIGIN.",
            xfo,
        )
    else:
        a.ok("Clickjacking protection present")

    xcto = r.header("x-content-type-options").lower()
    if xcto != "nosniff":
        a.add(
            "low",
            "X-Content-Type-Options is missing or not nosniff",
            "Browsers may MIME-sniff responses and execute content as a different type.",
            "Send X-Content-Type-Options: nosniff.",
            xcto or "(absent)",
        )
    else:
        a.ok("X-Content-Type-Options: nosniff")

    if not r.header("referrer-policy"):
        a.add(
            "low",
            "No Referrer-Policy",
            "URLs (which can contain tokens) leak to third parties through the Referer header.",
            "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
        )
    else:
        a.ok("Referrer-Policy present")

    if not r.header("permissions-policy") and not r.header("feature-policy"):
        a.add(
            "info",
            "No Permissions-Policy",
            "Powerful browser features (camera, microphone, geolocation) are not explicitly "
            "restricted.",
            "Send Permissions-Policy denying features the site does not use.",
        )

    banners = [
        "%s: %s" % (name, r.header(name))
        for name in (
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-aspnetmvc-version",
            "x-generator",
        )
        if r.header(name)
    ]
    if banners:
        a.add(
            "low",
            "Server / framework version disclosure",
            "Banner headers tell an attacker which software and version to target.",
            "Remove or genericize Server and X-Powered-By; disable framework version headers.",
            "; ".join(banners),
        )
    else:
        a.ok("No version-disclosing banner headers")

    missing_cross = [
        n
        for n in ("cross-origin-opener-policy", "cross-origin-resource-policy")
        if not r.header(n)
    ]
    if missing_cross:
        a.add(
            "info",
            "Cross-origin isolation headers missing",
            "COOP and CORP limit cross-window references and cross-origin resource embedding.",
            "Send Cross-Origin-Opener-Policy: same-origin and "
            "Cross-Origin-Resource-Policy: same-origin where the app allows it.",
            ", ".join(missing_cross),
        )
    else:
        a.ok("Cross-origin isolation headers present")


def check_cookies(a, *responses):
    cookies = []
    for r in responses:
        if r:
            cookies.extend(r.header_all("set-cookie"))
    if not cookies:
        return
    issues = []
    for raw in cookies[:6]:
        name, attrs = parse_cookie(raw)
        missing = []
        if a.client.target.scheme == "https" and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        samesite = attrs.get("samesite")
        if not samesite:
            missing.append("SameSite")
        elif samesite == "none" and "secure" not in attrs:
            missing.append("SameSite=None without Secure")
        if missing:
            issues.append("%s (missing: %s)" % (name, ", ".join(missing)))
    if issues:
        weak = any("Secure" in issue for issue in issues)
        a.add(
            "medium" if weak else "low",
            "Cookie flags are incomplete",
            "Cookies without Secure/HttpOnly/SameSite can be sent over HTTP, read by "
            "scripts, or attached to cross-site requests.",
            "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies.",
            "; ".join(issues[:4]),
        )
    else:
        a.ok("Session cookie flags set (Secure/HttpOnly/SameSite)")


def check_cors(a, path):
    probe_origin = "https://audit-probe.invalid"
    r = a.client.request("GET", path, {"Origin": probe_origin})
    if not r or not r.status:
        return
    acao = r.header("access-control-allow-origin")
    acac = r.header("access-control-allow-credentials").lower() == "true"
    if acao == probe_origin and acac:
        a.add(
            "high",
            "CORS reflects any Origin with credentials",
            "Any website can read authenticated responses from this endpoint with the "
            "victim's cookies.",
            "Allow only explicit, trusted origins; never reflect the Origin header when "
            "Access-Control-Allow-Credentials is true.",
            "Access-Control-Allow-Origin: %s; Allow-Credentials: true" % probe_origin,
        )
    elif acao == probe_origin:
        a.add(
            "medium",
            "CORS reflects arbitrary Origins",
            "The endpoint echoes back whatever Origin it receives, so any site can read "
            "unauthenticated responses.",
            "Validate Origin against an allowlist and return a fixed value.",
            "Access-Control-Allow-Origin: %s" % probe_origin,
        )
    elif acao == "*" and acac:
        a.add(
            "low",
            "CORS wildcard combined with credentials",
            "Browsers reject this combination, but it suggests a permissive CORS policy.",
            "Return an explicit origin allowlist instead of '*'.",
        )
    elif not acao:
        a.ok("No permissive CORS policy on the tested page")


def check_methods(a, path):
    r = a.client.request("OPTIONS", path)
    if r and 200 <= r.status < 400:
        allow = r.header("allow")
        risky = [m for m in ("PUT", "DELETE", "TRACE", "PATCH") if m in allow.upper()]
        if risky:
            a.add(
                "low",
                "Risky HTTP methods advertised",
                "The server advertises state-changing or diagnostic methods on this path.",
                "Restrict Allow to the methods the route actually needs.",
                "Allow: %s" % allow,
            )
    trace = a.client.request("TRACE", path)
    if trace and trace.status == 200:
        body = trace.body.decode("utf-8", "replace")
        if "TRACE /" in body or UA in body:
            a.add(
                "low",
                "HTTP TRACE is enabled",
                "TRACE reflects the request back, which can be abused to read HttpOnly "
                "cookies in some legacy browser/plugin combinations.",
                "Disable TRACE at the web server (Apache: TraceEnable Off; nginx: "
                "AllowMethods).",
            )


SENSITIVE = [
    (
        "/.git/config",
        "high",
        "Exposed Git repository metadata",
        "Block /.git/ at the web server and remove version control data from the web root.",
        _has(rb"\[core\]"),
    ),
    (
        "/.git/HEAD",
        "high",
        "Exposed Git repository metadata",
        "Block /.git/ at the web server and remove version control data from the web root.",
        lambda b, c: _texty(b, c) and b.startswith(b"ref: refs/"),
    ),
    (
        "/.env",
        "high",
        "Exposed environment file (.env)",
        "Move secrets out of the web root and rotate every credential the file contained.",
        _env_file,
    ),
    (
        "/.env.local",
        "high",
        "Exposed environment file (.env.local)",
        "Move secrets out of the web root and rotate every credential the file contained.",
        _env_file,
    ),
    (
        "/.env.production",
        "high",
        "Exposed environment file (.env.production)",
        "Move secrets out of the web root and rotate every credential the file contained.",
        _env_file,
    ),
    (
        "/.aws/credentials",
        "high",
        "Exposed AWS credentials file",
        "Remove the file from the web root and rotate the exposed keys immediately.",
        _has(rb"aws_access_key_id"),
    ),
    (
        "/id_rsa",
        "high",
        "Exposed private key",
        "Remove private keys from the web root and rotate the key pair.",
        _has(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ),
    (
        "/.ssh/id_rsa",
        "high",
        "Exposed SSH private key",
        "Remove private keys from the web root and rotate the key pair.",
        _has(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ),
    (
        "/.htpasswd",
        "high",
        "Exposed .htpasswd file",
        "Block hidden files at the web server and rotate the listed passwords.",
        lambda b, c: _texty(b, c) and bool(re.search(rb"(?m)^[^:\s]+:\$", b)),
    ),
    (
        "/terraform.tfstate",
        "high",
        "Exposed Terraform state",
        "Store state in a private backend and rotate any secrets it contains.",
        _has(rb'"terraform_version"|"resources"'),
    ),
    (
        "/wp-config.php.bak",
        "high",
        "Exposed WordPress configuration backup",
        "Delete backup copies of configuration files and rotate database credentials.",
        _has(rb"DB_PASSWORD"),
    ),
    (
        "/backup.sql",
        "high",
        "Exposed database dump",
        "Delete database dumps from the web root and rotate any credentials they contain.",
        _has(rb"(?i)CREATE TABLE|INSERT INTO"),
    ),
    (
        "/phpinfo.php",
        "high",
        "Exposed phpinfo() page",
        "Remove phpinfo pages from production; they leak paths, extensions and secrets.",
        _has(rb"PHP Version"),
    ),
    (
        "/actuator/env",
        "high",
        "Exposed Spring Boot Actuator environment",
        "Disable or authenticate Actuator endpoints; they leak configuration and secrets.",
        _has(rb"propertySources|activeProfiles"),
    ),
    (
        "/config/database.yml",
        "high",
        "Exposed database configuration",
        "Serve application configuration outside the web root and rotate its credentials.",
        lambda b, c: _texty(b, c)
        and re.search(rb"(?im)^\s*(production|development|adapter):", b) is not None
        and b"password" in b.lower(),
    ),
    (
        "/.DS_Store",
        "medium",
        "Exposed .DS_Store file",
        "Remove macOS metadata files from deployed content.",
        lambda b, c: b.startswith(b"\x00\x00\x00\x01Bud1"),
    ),
    (
        "/server-status",
        "medium",
        "Exposed Apache server-status",
        "Restrict server-status to localhost (Require ip 127.0.0.1).",
        _has(rb"Apache Server Status"),
    ),
    (
        "/docker-compose.yml",
        "medium",
        "Exposed docker-compose file",
        "Serve deployment manifests outside the web root.",
        _has(rb"(?m)^services:"),
    ),
    (
        "/web.config",
        "medium",
        "Exposed web.config",
        "Block *.config files at the web server.",
        _has(rb"<configuration"),
    ),
    (
        "/.svn/entries",
        "medium",
        "Exposed Subversion metadata",
        "Block /.svn/ at the web server.",
        _has(rb"(?m)^dir$|^[0-9]+$"),
    ),
    (
        "/sftp-config.json",
        "medium",
        "Exposed editor SFTP configuration",
        "Remove editor project files from deployed content and rotate the credentials.",
        _has(rb'"host"[\s\S]*"user"'),
    ),
    (
        "/Dockerfile",
        "low",
        "Exposed Dockerfile",
        "Serve build files outside the web root.",
        _has(rb"(?m)^FROM\s"),
    ),
    (
        "/composer.lock",
        "low",
        "Exposed composer.lock (exact dependency versions)",
        "Serve lock files outside the web root; they reveal vulnerable package versions.",
        _has(rb'"packages"|"packages-dev"'),
    ),
]


def check_exposed_files(a):
    tested = 0
    exposed = 0
    for path, severity, title, remediation, validator in SENSITIVE:
        if a.client.exhausted or a.client.stopped():
            break
        r = a.client.request("GET", path, {"Accept": "*/*"})
        tested += 1
        if not r or r.status not in (200, 206) or not r.body:
            continue
        try:
            hit = validator(r.body, r.content_type)
        except Exception:
            hit = False
        if hit:
            exposed += 1
            a.add(
                severity,
                title,
                "GET %s returned %d bytes matching the expected file content."
                % (path, len(r.body)),
                remediation,
                preview(r.body),
            )
    if tested and not exposed:
        a.ok("%d sensitive resource paths checked, none exposed" % tested)


def check_directory_listing(a):
    for p in ("/uploads/", "/files/", "/backup/", "/images/", "/admin/"):
        if a.client.exhausted or a.client.stopped():
            break
        r = a.client.request("GET", p)
        if not r or r.status != 200 or not r.body:
            continue
        body = r.body.lower()
        if b"index of /" in body or b"directory listing for" in body:
            a.add(
                "medium",
                "Open directory listing",
                "%s lists its contents, exposing files that were never meant to be browsable."
                % p,
                "Disable directory autoindex (nginx: autoindex off; Apache: Options -Indexes).",
                preview(r.body),
            )


def _html_text(r):
    if "html" not in r.content_type and b"<html" not in r.body[:600].lower():
        return ""
    return r.body.decode("utf-8", "replace")


def check_html(a, r):
    text = _html_text(r)
    if not text:
        return

    for form in re.findall(r"<form\b[^>]*>.*?</form>", text, re.I | re.S):
        if not re.search(r"type\s*=\s*[\"']?password", form, re.I):
            continue
        action = re.search(r"action\s*=\s*[\"']([^\"']*)", form, re.I)
        act = action.group(1) if action else ""
        if a.client.target.scheme == "http" or act.lower().startswith("http://"):
            a.add(
                "high",
                "Password form submits over plain HTTP",
                "Credentials typed into this form travel unencrypted and can be captured "
                "or altered in transit.",
                "Serve the form and its action over HTTPS only.",
                "action=%s" % (act or "(none)"),
            )
            break

    if a.client.target.scheme == "https":
        refs = re.findall(r"(?:src|href)\s*=\s*[\"'](http://[^\"']+)", text, re.I)
        refs = [u for u in refs if not re.match(r"http://(www\.)?w3\.org", u, re.I)]
        if refs:
            a.add(
                "medium",
                "Mixed content: http:// resources on an HTTPS page",
                "Browsers block or downgrade these, and they let a network attacker modify "
                "what loads on the page.",
                "Load all subresources over HTTPS and enable upgrade-insecure-requests.",
                ", ".join(refs[:3]),
            )


def check_sri(a, r):
    text = _html_text(r)
    if not text:
        return
    host = a.client.target.host
    external = 0
    weak = []
    for tag in re.findall(r"<script\b[^>]*>", text, re.I):
        src = re.search(r"src\s*=\s*[\"']([^\"']+)", tag, re.I)
        if not src:
            continue
        url = src.group(1).strip()
        if not url.lower().startswith(("http://", "https://", "//")):
            continue
        parsed = urllib.parse.urlsplit(url if not url.startswith("//") else "https:" + url)
        if not parsed.hostname or parsed.hostname == host:
            continue
        external += 1
        if "integrity=" not in tag.lower():
            weak.append(url)
    if weak:
        a.add(
            "low",
            "Third-party scripts without Subresource Integrity",
            "If the third-party host is compromised or serves modified code, the browser "
            "executes it on your origin.",
            "Add integrity and crossorigin attributes to every external script tag, or "
            "self-host the dependency.",
            ", ".join(weak[:3]),
        )
    elif external:
        a.ok("All %d third-party scripts pinned with SRI" % external)


def check_robots(a):
    r = a.client.request("GET", "/robots.txt")
    if r and r.status == 200 and r.body and "text/html" not in r.content_type:
        text = r.body.decode("utf-8", "replace")
        paths = re.findall(r"(?im)^\s*disallow:\s*(\S+)", text)
        paths = [p for p in paths if p not in ("", "/")]
        if paths:
            a.add(
                "info",
                "robots.txt advertises internal paths",
                "robots.txt is public and is a common starting point for attackers.",
                "Do not list sensitive paths in robots.txt; protect them with authentication "
                "instead.",
                ", ".join(paths[:5]),
            )
        a.ok("robots.txt returned")
    sec = a.client.request("GET", "/.well-known/security.txt")
    if sec and sec.status == 200:
        a.ok("security.txt published")


def sort_findings(findings):
    return sorted(findings, key=lambda f: SEVERITIES.index(f.severity))


def counts(findings):
    out = {s: 0 for s in SEVERITIES}
    for f in findings:
        out[f.severity] += 1
    return out


def grade(findings):
    score = max(0, 100 - sum(SEV_WEIGHT[f.severity] for f in findings))
    for floor, letter in ((95, "A"), (85, "B"), (70, "C"), (55, "D"), (35, "E"), (0, "F")):
        if score >= floor:
            return letter, score
    return "F", 0


def parse_target(raw):
    raw = (raw or "").strip()
    if not raw:
        raise TargetError("Enter a target URL.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise TargetError("Only http:// and https:// targets are supported.")
    if not parts.hostname:
        raise TargetError("The target must include a hostname.")
    if "@" in parts.netloc:
        raise TargetError("Do not embed credentials in the target URL.")
    if any(ch in parts.netloc for ch in (",", " ", "*")):
        raise TargetError(
            "This tool audits a single host. Wildcards and target lists are not supported."
        )
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(parts.scheme, parts.netloc, parts.hostname, port, path)


def run_audit(
    raw_target,
    timeout=10.0,
    delay=0.25,
    max_requests=60,
    insecure=False,
    progress=None,
    should_stop=None,
):
    target = parse_target(raw_target)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    client = Client(target, timeout, delay, max(max_requests, 10), insecure, should_stop)
    audit = Audit(client)

    def report(message):
        if progress:
            progress(message)

    main_resp = client.request("GET", target.path)
    if main_resp is None:
        cancelled = client.stopped()
        return Result(
            target.base,
            started,
            audit,
            "" if cancelled else "request budget exhausted",
            cancelled,
        )
    if not main_resp.status:
        return Result(target.base, started, audit, main_resp.error or "unreachable")

    redirect_resp = [None]

    phases = (
        ("HTTP scheme", lambda: redirect_resp.__setitem__(
            0, check_http_scheme(audit, target.path)
        )),
        ("TLS configuration", lambda: check_tls(audit)),
        ("security headers", lambda: check_headers(audit, main_resp)),
        ("cookie flags", lambda: check_cookies(audit, main_resp, redirect_resp[0])),
        ("CORS policy", lambda: check_cors(audit, target.path)),
        ("HTTP methods", lambda: check_methods(audit, target.path)),
        ("page content", lambda: check_html(audit, main_resp)),
        ("third-party scripts", lambda: check_sri(audit, main_resp)),
        ("sensitive files", lambda: check_exposed_files(audit)),
        ("directory listings", lambda: check_directory_listing(audit)),
        ("robots.txt", lambda: check_robots(audit)),
    )

    for label, phase in phases:
        if client.stopped():
            return Result(target.base, started, audit, "", True)
        report("checking " + label)
        phase()

    report("done")
    return Result(target.base, started, audit, "", client.stopped())


def in_scope(host, domain):
    host = (host or "").lower()
    domain = (domain or "").lower().strip().lstrip(".")
    if not domain:
        return True
    return host == domain or host.endswith("." + domain)


def load_inventory(path, scope_domain=None, limit=25):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.readlines()
    except OSError as e:
        raise TargetError("Cannot read %s (%s)." % (path, e))

    entries = []
    for line in raw:
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry not in entries:
            entries.append(entry)
    if not entries:
        raise TargetError("No targets found in %s." % path)

    cap = min(max(int(limit), 1), 200)
    targets = []
    skipped = []
    seen = set()
    for entry in entries:
        try:
            t = parse_target(entry)
        except TargetError:
            skipped.append(entry)
            continue
        if scope_domain and not in_scope(t.host, scope_domain):
            skipped.append(entry)
            continue
        if t.base in seen:
            continue
        seen.add(t.base)
        targets.append(t)

    if not targets:
        raise TargetError("No in-scope targets found in %s." % path)
    if len(targets) > cap:
        raise TargetError(
            "%d targets is above the limit of %d; raise --limit (maximum 200)."
            % (len(targets), cap)
        )
    return targets, skipped


def run_inventory(
    targets,
    timeout=10.0,
    delay=0.25,
    max_requests=60,
    insecure=False,
    progress=None,
    should_stop=None,
):
    inv = InventoryResult(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    total = len(targets)
    for index, target in enumerate(targets, 1):
        if should_stop and should_stop():
            break
        if progress:
            progress("auditing %s (%d/%d)" % (target.base, index, total))
        inv.results.append(
            run_audit(
                target.base,
                timeout=timeout,
                delay=delay,
                max_requests=max_requests,
                insecure=insecure,
                progress=progress,
                should_stop=should_stop,
            )
        )
    if progress:
        progress("done")
    return inv


def write_json(path, result):
    payload = {
        "tool": TOOL,
        "target": result.target,
        "started_at": result.started,
        "requests": result.audit.client.count,
        "grade": dict(zip(("letter", "score"), grade(result.audit.findings))),
        "summary": counts(result.audit.findings),
        "findings": [asdict(f) for f in sort_findings(result.audit.findings)],
        "passed": result.audit.passed,
    }
    payload["credit"] = CREDIT
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def finding_block_lines(f, level="###"):
    lines = ["", "%s %s — %s" % (level, SEV_LABEL[f.severity], f.title), "", f.detail]
    if f.evidence:
        lines += ["", "```", f.evidence, "```"]
    if f.remediation:
        lines += ["", "**Fix:** %s" % f.remediation]
    return lines


def write_markdown(path, result):
    c = counts(result.audit.findings)
    letter, score = grade(result.audit.findings)
    lines = [
        "# Security audit — %s" % result.target,
        "",
        "Generated %s by %s. Grade: **%s** (%d/100)." % (result.started, TOOL, letter, score),
        "",
        CREDIT.capitalize() + ".",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    lines += ["| %s | %d |" % (SEV_LABEL[s], c[s]) for s in SEVERITIES]
    lines += ["", "## Findings"]
    ordered = sort_findings(result.audit.findings)
    if not ordered:
        lines += ["", "No findings."]
    for f in ordered:
        lines += finding_block_lines(f)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_inventory_json(path, inv):
    targets = []
    all_findings = []
    for result in inv.results:
        findings = sort_findings(result.audit.findings)
        all_findings.extend(findings)
        letter, score = grade(findings)
        targets.append(
            {
                "target": result.target,
                "error": result.error,
                "requests": result.audit.client.count,
                "grade": {"letter": letter, "score": score},
                "summary": counts(findings),
                "findings": [asdict(f) for f in findings],
                "passed": result.audit.passed,
            }
        )
    payload = {
        "tool": TOOL,
        "started_at": inv.started,
        "count": len(inv.results),
        "skipped": inv.skipped,
        "aggregate": {
            "grade": dict(zip(("letter", "score"), grade(all_findings))),
            "summary": counts(all_findings),
        },
        "targets": targets,
    }
    payload["credit"] = CREDIT
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def write_inventory_markdown(path, inv):
    all_findings = [f for r in inv.results for f in r.audit.findings]
    c = counts(all_findings)
    letter, score = grade(all_findings)
    lines = [
        "# Inventory security audit",
        "",
        "Generated %s by %s." % (inv.started, TOOL),
        "",
        CREDIT.capitalize() + ".",
        "",
        "**%d targets** audited, aggregate grade **%s** (%d/100)."
        % (len(inv.results), letter, score),
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    lines += ["| %s | %d |" % (SEV_LABEL[s], c[s]) for s in SEVERITIES]
    lines += [
        "",
        "| Target | Grade | High | Med | Low | Info | Requests |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in inv.results:
        tc = counts(r.audit.findings)
        tl, _ = grade(r.audit.findings)
        lines.append(
            "| %s | %s | %d | %d | %d | %d | %d |"
            % (
                r.target,
                "failed" if r.error else tl,
                tc["high"],
                tc["medium"],
                tc["low"],
                tc["info"],
                r.audit.client.count,
            )
        )
    for r in inv.results:
        lines += ["", "## %s" % r.target]
        if r.error:
            lines += ["", "Audit failed: %s" % r.error]
            continue
        ordered = sort_findings(r.audit.findings)
        if not ordered:
            lines += ["", "No findings."]
        for f in ordered:
            lines += finding_block_lines(f)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def print_inventory_report(inv, scope, color):
    def emit(line="", sev=None):
        if sev and color:
            sys.stdout.write(SEV_COLOR[sev] + line + RESET + "\n")
        else:
            print(line)

    all_findings = [f for r in inv.results for f in r.audit.findings]
    c = counts(all_findings)
    letter, score = grade(all_findings)
    width = max([20] + [min(len(r.target), 44) for r in inv.results])

    emit("=" * 78)
    emit("siteaudit — inventory audit")
    emit(CREDIT)
    emit("source   : %s" % scope)
    emit("started  : %s" % inv.started)
    emit("hosts    : %d" % len(inv.results))
    if inv.skipped:
        emit("skipped  : %d (invalid or out of scope)" % len(inv.skipped))
    emit("=" * 78)
    print()
    print(
        "%-*s  %-5s %4s %3s %3s %4s %5s  %s"
        % (width, "target", "grade", "high", "med", "low", "info", "req", "status")
    )
    for r in inv.results:
        tc = counts(r.audit.findings)
        tl, _ = grade(r.audit.findings)
        print(
            "%-*s  %-5s %4d %3d %3d %4d %5d  %s"
            % (
                width,
                r.target[:width],
                "--" if r.error else tl,
                tc["high"],
                tc["medium"],
                tc["low"],
                tc["info"],
                r.audit.client.count,
                r.error or "ok",
            )
        )
    print()
    problems = [
        (r, f)
        for r in inv.results
        for f in sort_findings(r.audit.findings)
        if f.severity in ("high", "medium")
    ]
    if problems:
        print("Findings needing attention:")
        for r, f in problems:
            emit("  [%s] %s — %s" % (SEV_LABEL[f.severity], r.target, f.title), f.severity)
        print()
    emit(
        "Aggregate: %d high, %d medium, %d low, %d info — grade %s (%d/100)"
        % (c["high"], c["medium"], c["low"], c["info"], letter, score)
    )
    emit("Scope: every host in the list must be yours or covered by written authorization.")


def print_report(result, color):
    def emit(line="", sev=None):
        if sev and color:
            sys.stdout.write(SEV_COLOR[sev] + line + RESET + "\n")
        else:
            print(line)

    ordered = sort_findings(result.audit.findings)
    c = counts(result.audit.findings)
    letter, score = grade(result.audit.findings)

    emit("=" * 78)
    emit("siteaudit — authorized security audit")
    emit(CREDIT)
    emit("target   : %s" % result.target)
    emit("started  : %s" % result.started)
    emit("requests : %d (single host, rate-limited)" % result.audit.client.count)
    emit("=" * 78)
    print()

    if not ordered:
        emit("No findings.", "info")
    for f in ordered:
        emit("[%s] %s" % (SEV_LABEL[f.severity], f.title), f.severity)
        for line in f.detail.strip().splitlines():
            print("   " + line.strip())
        if f.evidence:
            print("   evidence: " + f.evidence)
        if f.remediation:
            print("   fix     : " + f.remediation)
        print()

    if result.audit.passed:
        print("Passed checks:")
        for p in result.audit.passed:
            print("   ok  " + p)
        print()

    emit(
        "Summary: %d high, %d medium, %d low, %d info — grade %s (%d/100)"
        % (c["high"], c["medium"], c["low"], c["info"], letter, score)
    )
    emit("Scope: only audit systems you own or have written permission to test.")


def build_parser():
    p = argparse.ArgumentParser(
        prog="siteaudit",
        description="Non-intrusive security audit for ONE host you own or are authorized "
        "to test. It checks misconfigurations and exposed files; it does not exploit them.",
        epilog="Examples: py -3 siteaudit.py https://example.com --authorized\n"
        "          py -3 siteaudit.py --inventory sites.txt --scope-domain example.com "
        "--authorized --md report.md\n\n" + CREDIT,
    )
    p.add_argument("target", nargs="?", help="site base URL, e.g. https://example.com")
    p.add_argument(
        "--authorized",
        action="store_true",
        help="confirm you own the target or have written permission to test it",
    )
    p.add_argument(
        "--version",
        action="version",
        version="%s (%s)" % (TOOL, CREDIT),
        help="print the version and exit",
    )
    p.add_argument(
        "--inventory",
        metavar="PATH",
        help="file with one site per line; every host must be yours or explicitly authorized",
    )
    p.add_argument(
        "--scope-domain",
        metavar="DOMAIN",
        help="reject any host that is not this domain or one of its subdomains",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=25,
        help="max hosts to audit from --inventory (default 25, hard cap 200)",
    )
    p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (s)")
    p.add_argument(
        "--delay", type=float, default=0.25, help="seconds between requests (minimum 0.1)"
    )
    p.add_argument(
        "--max-requests", type=int, default=60, help="hard cap on HTTP requests (default 60)"
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify TLS certificates for HTTP requests (local/self-signed testing)",
    )
    p.add_argument("--json", metavar="PATH", help="write findings as JSON")
    p.add_argument("--md", metavar="PATH", help="write findings as Markdown")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress the console report")
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print each audit phase to stderr while the scan runs",
    )
    return p


def _stderr_progress(message):
    sys.stderr.write("  %s\n" % message)
    sys.stderr.flush()


def confirm_authorization(target):
    if not sys.stdin.isatty():
        print(
            "Refusing to run: pass --authorized only if you own %s or have written\n"
            "permission to test it. Non-interactive runs require the flag." % target,
            file=sys.stderr,
        )
        return False
    print("You are about to audit: %s" % target)
    print("Only continue if you own this system or hold written authorization to test it.")
    try:
        answer = input("Type 'yes' to confirm: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nRefusing to run without confirmation.", file=sys.stderr)
        return False
    return answer == "yes"


def confirm_inventory(targets, scope):
    if not sys.stdin.isatty():
        print(
            "Refusing to run: --inventory requires --authorized in non-interactive runs.",
            file=sys.stderr,
        )
        return False
    print("About to audit %d hosts %s:" % (len(targets), scope))
    for t in targets[:10]:
        print("  - " + t.base)
    if len(targets) > 10:
        print("  ... and %d more" % (len(targets) - 10))
    print("Only continue if you own every host listed or hold written authorization for it.")
    try:
        answer = input("Type 'yes' to confirm: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nRefusing to run without confirmation.", file=sys.stderr)
        return False
    return answer == "yes"


def main_inventory(args):
    try:
        targets, skipped = load_inventory(args.inventory, args.scope_domain, args.limit)
    except TargetError as e:
        print(str(e), file=sys.stderr)
        return 3

    for entry in skipped[:10]:
        print("skipping unusable or out-of-scope entry: %s" % entry, file=sys.stderr)

    scope = "listed in %s" % args.inventory
    if args.scope_domain:
        scope += " and restricted to *.%s" % args.scope_domain.lstrip(".")
    if not args.authorized and not confirm_inventory(targets, scope):
        return 3
    if args.insecure:
        print("warning: TLS verification disabled for HTTP requests (--insecure)")

    inv = run_inventory(
        targets,
        timeout=args.timeout,
        delay=args.delay,
        max_requests=args.max_requests,
        insecure=args.insecure,
        progress=_stderr_progress if args.verbose else None,
    )
    inv.skipped = skipped
    if not inv.results:
        print("No audits completed.", file=sys.stderr)
        return 3

    if not args.quiet:
        print_inventory_report(inv, scope, not args.no_color and sys.stdout.isatty())
    if args.json:
        write_inventory_json(args.json, inv)
    if args.md:
        write_inventory_markdown(args.md, inv)

    if all(r.error for r in inv.results):
        return 3
    c = counts([f for r in inv.results for f in r.audit.findings])
    if c["high"]:
        return 2
    if c["medium"]:
        return 1
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.inventory and args.target:
        print("Pass either a target URL or --inventory, not both.", file=sys.stderr)
        return 3
    if not args.inventory and not args.target:
        print("Provide a target URL or --inventory PATH.", file=sys.stderr)
        return 3
    if args.inventory:
        return main_inventory(args)

    try:
        target = parse_target(args.target)
    except TargetError as e:
        print(str(e), file=sys.stderr)
        return 3

    if args.scope_domain and not in_scope(target.host, args.scope_domain):
        print(
            "%s is outside --scope-domain %s." % (target.host, args.scope_domain),
            file=sys.stderr,
        )
        return 3

    if not args.authorized and not confirm_authorization(target.base):
        return 3
    if args.insecure:
        print("warning: TLS verification disabled for HTTP requests (--insecure)")

    started_at = time.monotonic()
    result = run_audit(
        target.base,
        timeout=args.timeout,
        delay=args.delay,
        max_requests=args.max_requests,
        insecure=args.insecure,
        progress=_stderr_progress if args.verbose else None,
    )
    if args.verbose:
        sys.stderr.write("  finished in %.1fs\n" % (time.monotonic() - started_at))
    if result.error:
        print("Could not complete audit of %s (%s)." % (target.base, result.error), file=sys.stderr)
        return 3
    if not args.quiet:
        print_report(result, not args.no_color and sys.stdout.isatty())
    if args.json:
        write_json(args.json, result)
    if args.md:
        write_markdown(args.md, result)

    c = counts(result.audit.findings)
    if c["high"]:
        return 2
    if c["medium"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
