"""Origin-restricted, read-only iHealth transport; cookies remain in memory."""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .auth import AuthError, discover_profiles, firefox_jar

BASE = "https://ihealth.f5.com"
MAX_RESPONSE = 32 * 1024 * 1024


class FetchError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def ihealth_url(value):
    url = urllib.parse.urljoin(BASE, value)
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != "ihealth.f5.com"
            or parsed.port not in (None, 443) or parsed.username or parsed.password
            or not parsed.path.startswith("/qkview-analyzer/")):
        raise ValueError("Expected an HTTPS ihealth.f5.com/qkview-analyzer/ URL")
    if any(part in ("logoff", "delete", "edit", "hide") for part in parsed.path.split("/")):
        raise ValueError("Only read-only iHealth retrieval paths are accepted")
    return parsed._replace(fragment="").geturl()


class Client:
    def __init__(self, jar, opener=None, attempts=4, sleep=time.sleep):
        self.jar = jar
        self.opener = opener or urllib.request.build_opener(NoRedirect())
        self.attempts = attempts
        self.sleep = sleep

    @classmethod
    def from_firefox(cls, profile=None, container=0):
        profiles = [profile] if profile else discover_profiles()
        if not profiles:
            raise AuthError("No Firefox profiles found; supply --firefox-profile.")
        for candidate in profiles[:3]:
            try:
                client = cls(firefox_jar(candidate, container))
                page = client.get("/qkview-analyzer/")
                if "iHealth" not in page:
                    raise AuthError("iHealth login was not confirmed")
                return client
            except AuthError:
                if profile:
                    raise
        raise AuthError("Firefox iHealth login could not be reused. Sign in, open a QKView, and retry; use --firefox-profile for a non-default profile.")

    def get(self, path):
        url = ihealth_url(path)
        # Freeze the Firefox cookie selection: importing Set-Cookie responses caused
        # intermittent backend-affinity/login failures during the original investigation.
        for attempt in range(self.attempts):
            request = urllib.request.Request(url, headers={
                "Accept": "application/json, text/javascript, text/html, */*; q=0.01",
                "User-Agent": "F5-Migration-Evidence/1.0", "X-Requested-With": "XMLHttpRequest"})
            self.jar.add_cookie_header(request)
            try:
                with self.opener.open(request, timeout=60) as response:
                    if urllib.parse.urlsplit(response.url).hostname != "ihealth.f5.com":
                        raise AuthError("iHealth redirected to login")
                    raw = response.read(MAX_RESPONSE + 1)
                    if len(raw) > MAX_RESPONSE:
                        raise FetchError("Response exceeds 32 MiB; retrieve targeted evidence instead")
                    text = raw.decode("utf-8", "replace")
                    if "<title>Log in" in text or 'name="password"' in text and "auth0" in text:
                        raise AuthError("iHealth returned a login page")
                    return text
            except urllib.error.HTTPError as exc:
                exc.close()
                if exc.code in (301, 302, 303, 307, 308, 401):
                    if attempt + 1 == self.attempts:
                        raise AuthError("iHealth authentication required; refresh the Firefox login and resume this run.") from None
                elif exc.code in (429, 500, 502, 503, 504) and attempt + 1 < self.attempts:
                    self.sleep(min(2 ** attempt, 8))
                else:
                    raise FetchError(f"iHealth HTTP {exc.code}", exc.code) from None
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt + 1 == self.attempts:
                    raise FetchError("iHealth network request failed after retries") from None
                self.sleep(min(2 ** attempt, 8))
        raise FetchError("iHealth request failed")

    def search(self, url):
        parsed = urllib.parse.urlsplit(ihealth_url(url))
        args = urllib.parse.parse_qs(parsed.query)
        query = args.get("query", [""])[0].strip()
        if not query:
            raise ValueError("Search URL must contain a non-empty query parameter; use explicit QKView IDs otherwise")
        start, result, expected = 0, [], None
        while True:
            params = {"query": query, "showAll": args.get("showAll", ["false"])[0],
                      "start": start, "length": 100, "draw": 1,
                      "order_0_column": 0, "order_0_dir": "desc"}
            try:
                page = json.loads(self.get("/qkview-analyzer/qkviews?" + urllib.parse.urlencode(params)))
                rows = page["data"]
                count = int(page["recordsFiltered"])
                if not isinstance(rows, list):
                    raise ValueError()
            except (ValueError, KeyError, TypeError):
                raise FetchError("Unexpected iHealth search response; no IDs accepted") from None
            if expected is None:
                expected = count
            elif expected != count:
                raise FetchError("Search results changed while paging; rerun with explicit IDs")
            new = []
            for row in rows:
                qid = str(row[0] if isinstance(row, list) else row.get("id", ""))
                if not qid.isdigit() or qid in result or qid in new:
                    raise FetchError("Invalid/repeated QKView ID in paginated search results")
                new.append(qid)
            result.extend(new)
            if len(result) >= expected:
                return result
            if not new or start > 100000:
                raise FetchError("Incomplete search result pagination")
            start += len(rows)
