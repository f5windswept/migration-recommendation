"""Read Firefox's persistent and session cookies, without modifying the profile."""
import configparser
import http.cookiejar
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import sys
import tempfile


class AuthError(Exception):
    pass


HOSTS = {"ihealth.f5.com", ".ihealth.f5.com", ".f5.com"}
MAX_SESSION = 128 * 1024 * 1024


def decompress_mozlz4(data):
    """Decode Firefox's length-prefixed LZ4 block, including overlapping matches."""
    if len(data) < 12 or data[:8] != b"mozLz40\0":
        raise ValueError("Not a Firefox session snapshot")
    size = struct.unpack("<I", data[8:12])[0]
    if size > MAX_SESSION:
        raise ValueError("Firefox session snapshot exceeds size limit")
    src, out, i = data[12:], bytearray(), 0

    def length(initial):
        nonlocal i
        result = initial
        if initial == 15:
            while True:
                if i >= len(src):
                    raise ValueError("Truncated LZ4 length")
                value = src[i]
                i += 1
                result += value
                if value != 255:
                    break
        return result

    while i < len(src):
        token = src[i]
        i += 1
        count = length(token >> 4)
        if i + count > len(src) or len(out) + count > size:
            raise ValueError("Invalid LZ4 literal length")
        out.extend(src[i:i + count])
        i += count
        if i == len(src):
            break
        if i + 2 > len(src):
            raise ValueError("Truncated LZ4 offset")
        offset = src[i] | src[i + 1] << 8
        i += 2
        count = length(token & 15) + 4
        if not offset or offset > len(out) or len(out) + count > size:
            raise ValueError("Invalid LZ4 match")
        for _ in range(count):
            out.append(out[-offset])
    if len(out) != size:
        raise ValueError("Incomplete LZ4 block")
    return bytes(out)


def session_cookies(profile):
    # Session-only load-balancer cookies are NOT necessarily in cookies.sqlite.
    paths = [profile / "sessionstore-backups/recovery.jsonlz4",
             profile / "sessionstore-backups/recovery.baklz4",
             profile / "sessionstore.jsonlz4"]
    for path in paths:
        if not path.is_file():
            continue
        try:
            with path.open("rb") as stream:
                data = stream.read(MAX_SESSION + 1)
            if len(data) > MAX_SESSION:
                continue
            document = json.loads(decompress_mozlz4(data))
            cookies = list(document.get("cookies", []))
            for window in document.get("windows", []):
                cookies.extend(window.get("cookies", []))
            return [cookie for cookie in cookies if cookie.get("host") in HOSTS]
        except (ValueError, OSError, KeyError):
            continue
    return []


def discover_profiles(home=None):
    home = Path(home or Path.home())
    if sys.platform == "darwin":
        roots = [home / "Library/Application Support/Firefox"]
    elif sys.platform == "win32":
        roots = [Path(os.environ.get("APPDATA", home / "AppData/Roaming")) / "Mozilla/Firefox"]
    else:
        roots = [home / ".mozilla/firefox", home / "snap/firefox/common/.mozilla/firefox"]
    found = []
    for root in roots:
        parser = configparser.ConfigParser()
        parser.read(root / "profiles.ini")
        preferred = {parser[s].get("Default") for s in parser.sections() if s.startswith("Install")}
        for section in parser.sections():
            if not section.startswith("Profile") or "Path" not in parser[section]:
                continue
            item = parser[section]
            path = Path(item["Path"])
            if item.get("IsRelative", "1") == "1":
                path = root / path
            if (path / "cookies.sqlite").is_file():
                session = path / "sessionstore-backups/recovery.jsonlz4"
                modified = session.stat().st_mtime if session.exists() else 0
                found.append((item["Path"] in preferred, modified, path))
    return list(dict.fromkeys(item[2] for item in sorted(found, key=lambda x: (x[0], x[1]), reverse=True)))


def expiry_seconds(value):
    # Firefox versions/snapshots encountered in practice use seconds or milliseconds.
    value = int(value or 0)
    if value > 100_000_000_000_000:
        value //= 1_000_000
    elif value > 100_000_000_000:
        value //= 1_000
    return value or None


def make_cookie(host, path, secure, expiry, name, value):
    return http.cookiejar.Cookie(
        0, name, value, None, False, host, host.startswith("."), host.startswith("."),
        path, True, bool(secure), expiry_seconds(expiry), not bool(expiry), None, None, {})


def firefox_jar(profile, container=0):
    profile = Path(profile).expanduser().resolve()
    jar = http.cookiejar.CookieJar()
    source = profile / "cookies.sqlite"
    if not source.is_file():
        raise AuthError("Firefox profile has no cookies.sqlite; select --firefox-profile.")
    try:
        # Private temporary copy supports Firefox's exclusive lock and WAL mode.
        with tempfile.TemporaryDirectory(prefix="f5-migration-auth-") as directory:
            snapshot = Path(directory) / "cookies.sqlite"
            for suffix in ("", "-wal"):
                original = Path(str(source) + suffix)
                if original.exists():
                    target = Path(str(snapshot) + suffix)
                    shutil.copyfile(original, target)
                    target.chmod(0o600)
            db = sqlite3.connect(snapshot.as_uri() + "?mode=ro", uri=True)
            try:
                rows = db.execute(
                    "SELECT host,path,isSecure,expiry,name,value,originAttributes "
                    "FROM moz_cookies WHERE host IN ('ihealth.f5.com','.ihealth.f5.com','.f5.com')")
                for host, path, secure, expiry, name, value, attrs in rows:
                    # Do not mix Firefox containers or partitioned authentication contexts.
                    attrs = dict(part.split("=", 1) for part in (attrs or "").lstrip("^").split("&") if "=" in part)
                    if int(attrs.get("userContextId", 0)) != container or attrs.get("partitionKey") or attrs.get("privateBrowsingId", "0") != "0":
                        continue
                    jar.set_cookie(make_cookie(host, path, secure, expiry, name, value))
            finally:
                db.close()
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise AuthError("Could not read a consistent Firefox cookie snapshot. Retry or select the active profile.") from exc
    for cookie in session_cookies(profile):
        attrs = cookie.get("originAttributes", {})
        if attrs.get("userContextId", 0) != container or attrs.get("partitionKey") or attrs.get("privateBrowsingId", 0):
            continue
        jar.set_cookie(make_cookie(cookie["host"], cookie.get("path", "/"),
                                   cookie.get("secure", False), cookie.get("expiry"),
                                   cookie["name"], cookie["value"]))
    if not any(c.name == "JSESSIONID" and "ihealth" in c.domain for c in jar):
        raise AuthError("No iHealth session found. Sign in to iHealth in Firefox and open a QKView.")
    return jar
