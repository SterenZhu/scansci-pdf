"""CARSI (Shibboleth/SAML) federated authentication for publisher access.

Provides institutional login through CARSI federation, supporting
publishers like Elsevier, Springer Nature, Wiley, ACS, etc.
"""

from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from ..config import DATA_DIR
from ..log import get_logger
from ..publisher_strategies import (
    _IDP_MAP,
    _AUTH_KEYWORDS,
    _AUTH_TITLES,
    _INSTITUTION_SEARCH_SELECTORS,
    _SSO_LINK_FINDER_JS,
    _INSTITUTION_CLICK_JS,
)

log = get_logger()

_PUBLISHER_CONFIGS_FILE = DATA_DIR / "publisher_carsi.json"
_PKG_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_PKG_PUBLISHER_CONFIGS_FILE = _PKG_DATA_DIR / "publisher_carsi.json"

_PORTAL_PUBLISHER_ALIASES: dict[str, tuple[str, ...]] = {
    "sciencedirect": ("ScienceDirect", "Elsevier"),
    "springer": ("Springer Nature", "SpringerLink", "Springer"),
    "nature": ("Nature", "Springer Nature"),
    "ieee": ("IEEE-IET ELECTRONIC LIBRARY", "IEEE Xplore", "IEEE"),
    "wiley": ("Wiley Online Library", "Wiley"),
    "tandfonline": ("Taylor & Francis", "Taylor and Francis"),
    "asce": ("ASCE Library", "ASCE"),
    "sage": ("SAGE Journals", "SAGE"),
}

_PORTAL_RESOURCE_URL_JS = r"""
(terms) => {
    const wanted = terms.map(value => value.toLowerCase());
    const nodes = [...document.querySelectorAll('a, button')];
    const onDetailPage = document.location.pathname.includes('resourceDetail');
    const matchedContainer = (node, term) => {
        let container = node;
        for (let depth = 0; depth < 6 && container; depth++, container = container.parentElement) {
            const text = (container.innerText || '').replace(/\s+/g, ' ').trim().toLowerCase();
            if (text.includes(term)) return container;
        }
        return null;
    };
    for (const term of wanted) {
        for (const node of nodes) {
            const action = (node.innerText || node.textContent || '').trim().toLowerCase();
            const href = node.getAttribute('href') || '';
            const onclick = node.getAttribute('onclick') || '';
            const isAccess = action.includes('访问资源') || action.includes('access resource')
                || action === 'access' || href.includes('gotoResource') || onclick.includes('gotoResource');
            const container = matchedContainer(node, term);
            const containerText = (container?.innerText || '').toLowerCase();
            if (!isAccess || (!onDetailPage && !container) || containerText.includes('ieee-wiley')) continue;
            if (href && !href.toLowerCase().startsWith('javascript:')) {
                return new URL(href, document.location.href).href;
            }
            const match = `${href} ${onclick}`.match(/gotoResource\s*\(\s*['\"]([^'\"]+)['\"]\s*\)/i);
            if (match) return new URL(match[1], document.location.href).href;
        }
    }
    // The resource listing links to a detail page first; the actual
    // gotoResource action is only present on that detail page.
    for (const node of document.querySelectorAll('a[href]')) {
        const text = (node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim().toLowerCase();
        const href = node.getAttribute('href') || '';
        if (wanted.some(term => text.includes(term)) && href.includes('resourceDetail')
            && !text.includes('ieee-wiley')) {
            return new URL(href, document.location.href).href;
        }
    }
    return null;
}
"""

_PORTAL_IDP_SUBMIT_JS = r"""
(entityID) => {
    const form = document.querySelector('form#idpForm');
    const input = document.querySelector('input[name="entityID"], input#hid-inp');
    if (!form || !input) return false;
    input.value = entityID;
    form.submit();
    return true;
}
"""

_PAGE_PDF_FETCH_JS = r"""
async (pdfUrl) => {
    try {
        const response = await fetch(pdfUrl, {
            credentials: 'include',
            headers: {'Accept': 'application/pdf'}
        });
        const contentType = response.headers.get('content-type') || '';
        if (!response.ok) return {status: response.status, contentType, data: ''};
        const bytes = new Uint8Array(await response.arrayBuffer());
        if (bytes.length < 5000) return {status: response.status, contentType, data: ''};
        let binary = '';
        const chunkSize = 0x8000;
        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
        }
        return {status: response.status, contentType, data: btoa(binary)};
    } catch (error) {
        return {status: 0, contentType: '', data: '', error: String(error)};
    }
}
"""


@dataclass
class PublisherCARSIConfig:
    name: str
    domains: list[str]
    login_url: str
    search_selector: str
    result_selector: str
    success_url_pattern: str
    pdf_pattern: str


def _load_publisher_configs() -> dict[str, PublisherCARSIConfig]:
    # Try package data first, then user data dir
    config_file = _PKG_PUBLISHER_CONFIGS_FILE if _PKG_PUBLISHER_CONFIGS_FILE.exists() else _PUBLISHER_CONFIGS_FILE
    if not config_file.exists():
        return {}
    data = json.loads(config_file.read_text(encoding="utf-8"))
    configs = {}
    for key, val in data.items():
        configs[key] = PublisherCARSIConfig(**val)
    return configs


def detect_publisher(url: str) -> str | None:
    """Detect publisher key from a URL."""
    hostname = urlparse(url).hostname or ""
    configs = _load_publisher_configs()
    for key, cfg in configs.items():
        for domain in cfg.domains:
            if domain in hostname:
                return key
    return None


def _hostname_matches(hostname: str, expected_domain: str) -> bool:
    """Match an exact publisher domain or one of its subdomains."""
    host = hostname.lower().strip(".")
    expected = expected_domain.lower().strip(".")
    return bool(expected and (host == expected or host.endswith(f".{expected}")))


def _canonical_article_url(publisher: str, article_url: str) -> str:
    """Return a direct publisher article URL when a DOI resolver intermediary is known."""
    if publisher == "sciencedirect":
        pii = _extract_pii(article_url)
        if pii:
            return f"https://www.sciencedirect.com/science/article/pii/{pii}"
    return article_url


def _extract_pii(url: str) -> str:
    """Extract an Elsevier PII while preserving it across transient redirects."""
    match = re.search(r"/pii/([A-Z0-9]+)", url, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_ieee_article_id(url: str) -> str:
    """Extract an IEEE article number from a canonical document URL."""
    match = re.search(r"/document/(\d+)", url, re.IGNORECASE)
    return match.group(1) if match else ""


class CARSIClient:
    """Manages CARSI/Shibboleth federated authentication with academic publishers."""

    _login_lock = threading.Lock()

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self._sessions: dict[str, requests.Session] = {}
        self._publisher_configs = _load_publisher_configs()
        self._cookie_dir = Path(config.get("cache_dir", str(DATA_DIR / "cache"))) / "carsi_cookies"
        self._cookie_dir.mkdir(parents=True, exist_ok=True)

    def _cookie_path(self, publisher: str) -> Path:
        return self._cookie_dir / f"{publisher}.json"

    def _get_session(self, publisher: str) -> requests.Session:
        if publisher not in self._sessions:
            sess = requests.Session()
            sess.trust_env = False
            sess.headers.update({
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            })
            self._sessions[publisher] = sess
        return self._sessions[publisher]

    def _portal_terms(self, publisher: str) -> list[str]:
        """Return stable display-name aliases used to find a portal resource."""
        terms = list(_PORTAL_PUBLISHER_ALIASES.get(publisher, ()))
        cfg = self._publisher_configs.get(publisher)
        if cfg and cfg.name not in terms:
            terms.insert(0, cfg.name)
        return terms or [publisher]

    def _portal_resource_url(self, page: Any, publisher: str) -> str | None:
        """Discover the portal redirect URL from visible resource text.

        CARSI resource identifiers are intentionally not hard-coded: the portal
        may change them, while publisher display names remain discoverable.
        """
        try:
            value = page.evaluate(_PORTAL_RESOURCE_URL_JS, self._portal_terms(publisher))
        except Exception:
            return None
        return value if isinstance(value, str) and value.startswith(("http://", "https://")) else None

    def _start_portal_login(self, page: Any) -> bool:
        """Submit the portal's own IdP selection form when it is displayed."""
        try:
            hostname = (urlparse(page.url).hostname or "").lower()
            path = urlparse(page.url).path.lower()
        except Exception:
            return False
        if hostname != "ds.carsi.edu.cn" or "/login/" not in path:
            return False

        entity_id = str(self.config.get("carsi_idp_entity_id", "") or "").strip()
        if not entity_id.startswith(("http://", "https://")):
            log.info(
                "   [CARSI-Portal] School selection required; set carsi_idp_entity_id "
                "or select the institution manually"
            )
            return False
        try:
            submitted = bool(page.evaluate(_PORTAL_IDP_SUBMIT_JS, entity_id))
        except Exception as exc:
            log.info(f"   [CARSI-Portal] IdP form submission failed: {exc}")
            return False
        if submitted:
            log.info("   [CARSI-Portal] Institution selected; complete school login if requested")
        return submitted

    @staticmethod
    def _context_pdf_request(context: Any, pdf_url: str, referer: str) -> bytes | None:
        """Request a PDF through the authenticated browser context."""
        try:
            response = context.request.get(
                pdf_url,
                headers={"Accept": "application/pdf", "Referer": referer},
                timeout=30000,
            )
            if response.status >= 400:
                log.info(f"   [CARSI-Portal] Authenticated PDF request returned HTTP {response.status}")
                return None
            content_type = response.headers.get("content-type", "").lower()
            body = response.body()
            if ("pdf" in content_type or body[:5] == b"%PDF-") and len(body) > 5000 and body[:5] == b"%PDF-":
                return body
            log.info(
                "   [CARSI-Portal] Authenticated PDF response rejected: "
                f"status={response.status}, content-type={content_type or '(none)'}, "
                f"size={len(body)}, signature={body[:5]!r}"
            )
        except Exception as exc:
            log.info(f"   [CARSI-Portal] Authenticated PDF request failed: {exc}")
        return None

    @staticmethod
    def _page_pdf_request(page: Any, pdf_url: str) -> bytes | None:
        """Fetch PDF bytes inside the authenticated publisher page."""
        try:
            result = page.evaluate(_PAGE_PDF_FETCH_JS, pdf_url)
            encoded = result.get("data", "") if isinstance(result, dict) else ""
            if encoded:
                body = base64.b64decode(encoded)
                if len(body) > 5000 and body[:5] == b"%PDF-":
                    return body
            if isinstance(result, dict):
                log.info(
                    "   [CARSI-Browser] In-page PDF request rejected: "
                    f"status={result.get('status', 0)}, "
                    f"content-type={result.get('contentType', '') or '(none)'}"
                )
        except Exception as exc:
            log.info(f"   [CARSI-Browser] In-page PDF request failed: {exc}")
        return None

    def _enter_via_portal(self, page: Any, publisher: str) -> bool:
        """Enter *publisher* through a configured CARSI discovery portal.

        The user may finish an ordinary institutional login in the visible
        browser. A single bounded wait is used; failure never falls through to
        the publisher-side organization finder in the same attempt.
        """
        portal_url = str(self.config.get("carsi_portal_url", "") or "").strip()
        if not portal_url:
            return False
        if not portal_url.startswith(("http://", "https://")):
            log.info("   [CARSI-Portal] carsi_portal_url must use http(s)")
            return False

        timeout_seconds = int(self.config.get("carsi_portal_timeout", 120) or 120)
        timeout_seconds = max(10, min(timeout_seconds, 600))
        deadline = time.monotonic() + timeout_seconds

        log.info(f"   [CARSI-Portal] Opening resource portal: {portal_url}")
        try:
            page.goto(portal_url, wait_until="domcontentloaded", timeout=60000)
        except Exception as exc:
            log.info(f"   [CARSI-Portal] Portal navigation failed: {exc}")
            return False

        self._start_portal_login(page)

        prompted = False
        resource_url: str | None = None
        while time.monotonic() < deadline:
            resource_url = self._portal_resource_url(page, publisher)
            if resource_url:
                break
            if not prompted:
                names = " / ".join(self._portal_terms(publisher))
                log.info(
                    f"   [CARSI-Portal] Complete institutional login if requested; "
                    f"waiting for resource: {names}"
                )
                prompted = True
            time.sleep(2)

        if not resource_url:
            log.info("   [CARSI-Portal] Resource/login wait timed out; stopping this CARSI attempt")
            return False

        cfg = self._publisher_configs.get(publisher)
        expected_domain = cfg.success_url_pattern if cfg else ""
        # The listing normally links to resourceDetail.php, whose access
        # button then links to gotoResource.php. Follow these discovered links
        # in the same tab so response capture remains attached.
        for _hop in range(3):
            log.info(f"   [CARSI-Portal] Following resource route: {resource_url[:100]}")
            try:
                page.goto(resource_url, wait_until="domcontentloaded", timeout=60000)
            except Exception as exc:
                log.info(f"   [CARSI-Portal] Resource navigation failed: {exc}")
                return False

            while time.monotonic() < deadline:
                try:
                    hostname = (urlparse(page.url).hostname or "").lower()
                except Exception:
                    return False
                if _hostname_matches(hostname, expected_domain):
                    log.info(f"   [CARSI-Portal] Publisher session established: {hostname}")
                    return True
                next_url = self._portal_resource_url(page, publisher)
                if next_url and next_url != resource_url:
                    resource_url = next_url
                    break
                time.sleep(2)
            else:
                break

        log.info("   [CARSI-Portal] Publisher redirect timed out; stopping this CARSI attempt")
        return False

    def login(self, publisher: str, force: bool = False) -> bool:
        """Ensure we have a valid CARSI session for the given publisher."""
        with self._login_lock:
            if not force and self._try_load_cookies(publisher):
                log.info(f"   [CARSI] Loaded saved cookies for {publisher}")
                return True
            log.info(f"   [CARSI] No valid session for {publisher}. Opening browser...")
            return self._browser_login(publisher)

    def fetch(self, url: str, **kwargs) -> requests.Response | None:
        """Fetch a URL using CARSI-authenticated session."""
        publisher = detect_publisher(url)
        if not publisher:
            return None

        if not self.login(publisher):
            return None

        sess = self._get_session(publisher)
        kwargs.setdefault("timeout", 30)
        kwargs.setdefault("allow_redirects", True)
        try:
            return sess.get(url, **kwargs)
        except requests.RequestException as e:
            log.warning(f"   [CARSI] Fetch failed: {e}")
            return None

    def download_via_browser(self, doi: str, article_url: str, output_path: Path) -> dict[str, Any] | None:
        """Download PDF via CloakBrowser with CARSI auth."""
        return self._download_via_cloakbrowser(doi, article_url, output_path)

    def _download_via_cloakbrowser(self, doi: str, article_url: str, output_path: Path) -> dict[str, Any] | None:
        """Download PDF via CloakBrowser with CARSI auth. Single session: login + download."""
        publisher = detect_publisher(article_url)
        if not publisher:
            return None
        cfg = self._publisher_configs.get(publisher)
        if not cfg:
            return None

        try:
            from ..browser_backend import launch  # noqa: F401
            from ..browser_backend import is_available as _browser_backend_available
            if not _browser_backend_available():
                log.info("   [CARSI-Browser] no browser backend available")
                return None
        except ImportError:
            log.info("   [CARSI-Browser] no browser backend available")
            return None

        idp_name = self.config.get("carsi_idp_name", "")
        if not idp_name:
            log.info("   [CARSI-Browser] No carsi_idp_name configured")
            return None

        idp_en = _IDP_MAP.get(idp_name, idp_name)

        from ..pdf_utils import is_pdf_file, success as _success

        # Serialize browser opens across threads — only one browser at a time
        with self._login_lock:
            log.info(f"   [CARSI-Browser] Opening browser for {publisher}...")
            try:
                from ..publisher_strategies import _visible_browser, _save_all_cookie_formats

                with _visible_browser(self.config, publisher, viewport=None) as (context, page):
                    def _try_save_captured() -> dict[str, Any] | None:
                        """If a PDF was captured, save and validate it."""
                        if captured_pdf:
                            output_path.parent.mkdir(parents=True, exist_ok=True)
                            output_path.write_bytes(captured_pdf[-1])
                            if is_pdf_file(output_path):
                                return _success(doi, output_path, "CARSI-Browser")
                        return None

                    # Restore saved cookies if any (supplements persistent profile)
                    cookie_file = self._cookie_path(publisher)
                    if cookie_file.exists():
                        try:
                            saved = json.loads(cookie_file.read_text(encoding="utf-8"))
                            pw_cookies = []
                            for c in saved:
                                pw_c = {"name": c["name"], "value": c["value"], "domain": c.get("domain", ""), "path": c.get("path", "/")}
                                if pw_c["domain"]:
                                    pw_cookies.append(pw_c)
                            if pw_cookies:
                                context.add_cookies(pw_cookies)
                                log.info(f"   [CARSI-Browser] Restored {len(pw_cookies)} cookies from file")
                        except Exception:
                            pass

                    # Capture PDF from network
                    captured_pdf = []
                    def on_response(response):
                        try:
                            ct = response.headers.get("content-type", "")
                            url = response.url
                            is_pdf_ct = "pdf" in ct.lower() or "octet-stream" in ct.lower()
                            is_pdf_url = url.lower().endswith(".pdf") or "/pdfdirect/" in url or "/doi/pdf/" in url
                            if not (is_pdf_ct or is_pdf_url):
                                return
                            if response.status >= 400:
                                return
                            body = response.body()
                            if len(body) > 5000 and body[:4] == b"%PDF-":
                                captured_pdf.append(body)
                                log.info(f"   [CARSI-Browser] PDF captured: {len(body)} bytes")
                        except Exception:
                            pass
                    page.on("response", on_response)

                    # Optional Step 0: enter through a central CARSI resource
                    # portal. This deliberately replaces publisher-side WAYF
                    # discovery for the current attempt.
                    portal_configured = bool(str(self.config.get("carsi_portal_url", "") or "").strip())
                    portal_authenticated = False
                    if portal_configured:
                        portal_authenticated = self._enter_via_portal(page, publisher)
                        if not portal_authenticated:
                            return None
                        try:
                            _save_all_cookie_formats(context.cookies(), publisher, self.config)
                        except Exception:
                            pass

                        # ScienceDirect's article HTML commonly triggers an
                        # interstitial even after institutional SSO. Reuse the
                        # authenticated browser context to request the official
                        # PDF endpoint directly before navigating the HTML page.
                        direct_article_url = _canonical_article_url(publisher, article_url)
                        if publisher == "sciencedirect":
                            direct_pii = _extract_pii(direct_article_url)
                            if direct_pii:
                                direct_pdf_url = (
                                    "https://www.sciencedirect.com/science/article/pii/"
                                    f"{direct_pii}/pdfft"
                                )
                                pdf_body = self._context_pdf_request(context, direct_pdf_url, direct_article_url)
                                if pdf_body:
                                    captured_pdf.append(pdf_body)
                                    saved = _try_save_captured()
                                    if saved:
                                        return saved

                        article_url = direct_article_url

                    # Step 1: Navigate to article page first (gets Cloudflare clearance)
                    log.info(f"   [CARSI-Browser] Loading article: {article_url[:60]}")
                    try:
                        page.goto(article_url, wait_until="domcontentloaded", timeout=60000)
                        time.sleep(5)
                    except Exception:
                        pass

                    title = page.title()
                    url = page.url
                    log.info(f"   [CARSI-Browser] Page: '{title[:40]}' {url[:60]}")

                    # Wait for Cloudflare challenge to resolve (visible stealth browser can pass it)
                    from ..network import is_cloudflare_challenge
                    for _cf_wait in range(12):
                        if is_cloudflare_challenge(page.title() or ""):
                            log.info(f"   [CARSI-Browser] Cloudflare challenge detected, waiting... ({_cf_wait+1}/12)")
                            time.sleep(5)
                        else:
                            break
                    else:
                        log.info("   [CARSI-Browser] Cloudflare challenge did not resolve")

                    # Step 1b: Check if restored cookies already grant access
                    has_cookies = cookie_file.exists()
                    needs_login = False
                    try:
                        needs_login = page.evaluate("""
                            () => {
                                if (!document.body) return true;
                                const body = (document.body.innerText || '').toLowerCase();
                                const hasPaywall = body.includes('purchase') || body.includes('subscribe')
                                    || body.includes('access through your institution')
                                    || body.includes('sign in to access')
                                    || body.includes('buy this article');
                                const hasPdf = !!document.querySelector('a[href*="pdf"], a[href*="download"], iframe[src*="pdf"]');
                                return hasPaywall && !hasPdf;
                            }
                        """)
                    except Exception as _e:
                        log.info(f"   [CARSI-Browser] paywall check error (likely Cloudflare): {_e}")
                        needs_login = True

                    # Even if page looks accessible, verify cookies work by
                    # trying a quick pdfft probe. ScienceDirect may accept
                    # expired cookies without showing a paywall, but return
                    # HTML instead of PDF for /pdfft requests.
                    cookies_valid = portal_authenticated
                    if has_cookies and not needs_login and not portal_authenticated:
                        pii_from_url = ""
                        _pm = re.search(r"pii/([A-Z0-9]+)", page.url)
                        if _pm:
                            pii_from_url = _pm.group(1)
                        if pii_from_url:
                            try:
                                probe_ok = page.evaluate(f"""
                                    (async () => {{
                                        try {{
                                            const r = await fetch('/science/article/pii/{pii_from_url}/pdfft',
                                                {{credentials: 'include', headers: {{'Accept': 'application/pdf'}}}});
                                            const ct = r.headers.get('content-type') || '';
                                            return r.ok && ct.includes('pdf');
                                        }} catch(e) {{ return false; }}
                                    }})()
                                """)
                                cookies_valid = bool(probe_ok)
                                if cookies_valid:
                                    log.info("   [CARSI-Browser] Cookie probe OK, skipping login")
                                else:
                                    log.info("   [CARSI-Browser] Cookie probe failed, re-login needed")
                            except Exception:
                                log.info("   [CARSI-Browser] Cookie probe error, will re-login")

                    if not cookies_valid:
                        # Step 2: Navigate to "Institutional login" link on article page
                        sso_href = page.evaluate(_SSO_LINK_FINDER_JS)
                        if sso_href:
                            log.info(f"   [CARSI-Browser] Navigating to SSO: {sso_href[:80]}")
                            try:
                                page.goto(sso_href, wait_until="domcontentloaded", timeout=30000)
                            except Exception:
                                pass
                        else:
                            log.info("   [CARSI-Browser] No SSO link found, trying direct login URL...")
                            try:
                                page.goto(cfg.login_url, wait_until="domcontentloaded", timeout=30000)
                            except Exception:
                                pass

                        time.sleep(8)

                        # Step 3: Search for institution in the WAYF page
                        search_input = page.query_selector('#searchInstitution')
                        if not search_input:
                            for sel in _INSTITUTION_SEARCH_SELECTORS[1:]:  # skip #searchInstitution (already tried)
                                search_input = page.query_selector(sel)
                                if search_input:
                                    break

                        if search_input:
                            search_input.fill(idp_en)
                            time.sleep(3)
                            log.info(f"   [CARSI-Browser] Searched for '{idp_en}'")

                            # Click matching institution
                            clicked = page.evaluate(_INSTITUTION_CLICK_JS, idp_en)
                            if clicked:
                                log.info(f"   [CARSI-Browser] Selected: {clicked}")
                                time.sleep(5)
                            else:
                                search_input.press("Enter")
                                time.sleep(3)
                        else:
                            log.info("   [CARSI-Browser] No institution search box found")

                        # Step 4: Wait for CAS login
                        _ak = _AUTH_KEYWORDS
                        _at = _AUTH_TITLES

                        url = page.url
                        title = page.title()
                        if any(x in url.lower() for x in _ak) or any(x in title for x in _at):
                            log.info("   [CARSI-Browser] CAS login required. Please log in...")
                            for i in range(100):
                                time.sleep(3)
                                try:
                                    title = page.title()
                                    url = page.url
                                except Exception:
                                    return None
                                is_auth = any(x in title for x in _at)
                                is_auth_url = any(x in url.lower() for x in _ak)
                                if not is_auth and not is_auth_url:
                                    # Login success - save cookies in all formats + bridge to CloakBrowser
                                    try:
                                        cookies = context.cookies()
                                        _save_all_cookie_formats(cookies, publisher, self.config)
                                    except Exception:
                                        pass
                                    break
                            else:
                                log.info("   [CARSI-Browser] Login timed out")
                                return None
                        else:
                            log.info("   [CARSI-Browser] Already authenticated")

                    # Step 5: Navigate to article (with CARSI auth now)
                    time.sleep(2)
                    log.info(f"   [CARSI-Browser] Navigating to article: {article_url[:60]}")
                    try:
                        page.goto(article_url, wait_until="domcontentloaded", timeout=30000)
                        time.sleep(5)
                    except Exception:
                        pass

                    # Check for PDF via network capture
                    saved = _try_save_captured()
                    if saved:
                        return saved

                    # Step 6: Try direct PDF URL
                    pii_value = _extract_pii(page.url) or _extract_pii(article_url)
                    article_id = _extract_ieee_article_id(page.url) or _extract_ieee_article_id(article_url)
                    pdf_pattern = (
                        cfg.pdf_pattern
                        .replace("{doi}", doi)
                        .replace("{pii}", pii_value)
                        .replace("{article_id}", article_id)
                    )
                    if pdf_pattern and not pdf_pattern.startswith("http"):
                        pdf_url = f"https://{cfg.domains[0]}{pdf_pattern}"
                    else:
                        pdf_url = pdf_pattern

                    if pdf_url and "{pii}" not in pdf_url:
                        log.info(f"   [CARSI-Browser] Trying PDF: {pdf_url[:80]}")
                        captured_pdf.clear()
                        pdf_body = self._page_pdf_request(page, pdf_url)
                        if pdf_body:
                            captured_pdf.append(pdf_body)
                            saved = _try_save_captured()
                            if saved:
                                return saved
                        try:
                            page.goto(pdf_url, wait_until="commit", timeout=30000)
                            time.sleep(5)
                        except Exception:
                            pass
                        # Chrome's built-in PDF viewer may consume the document
                        # without exposing response.body() to the page listener.
                        # Once ScienceDirect has issued its signed asset URL,
                        # fetch that exact URL through the same browser context.
                        if not captured_pdf:
                            current_pdf_url = page.url
                            if "pdf.sciencedirectassets.com" in current_pdf_url:
                                pdf_body = self._context_pdf_request(context, current_pdf_url, article_url)
                                if pdf_body:
                                    captured_pdf.append(pdf_body)
                        saved = _try_save_captured()
                        if saved:
                            return saved

                    # Step 7: Find PDF link in HTML
                    from ..pdf_utils import extract_pdf_url_from_html
                    html = page.content()
                    found_pdf = extract_pdf_url_from_html(html, page.url)
                    if found_pdf:
                        log.info(f"   [CARSI-Browser] Found PDF link: {found_pdf[:80]}")
                        captured_pdf.clear()
                        try:
                            page.goto(found_pdf, wait_until="commit", timeout=30000)
                            time.sleep(5)
                        except Exception:
                            pass
                        saved = _try_save_captured()
                        if saved:
                            return saved

                    # Step 8: Click PDF button
                    click_result = page.evaluate("""
                        () => {
                            const links = document.querySelectorAll('a');
                            for (const a of links) {
                                const href = (a.getAttribute('href') || '').toLowerCase();
                                const text = (a.innerText || '').toLowerCase();
                                if ((href.includes('pdf') || href.includes('download')) && !href.includes('supplement')) {
                                    if (text.includes('pdf') || text.includes('download')) {
                                        a.click();
                                        return a.href;
                                    }
                                }
                            }
                            return null;
                        }
                    """)
                    if click_result:
                        log.info(f"   [CARSI-Browser] Clicked: {str(click_result)[:80]}")
                        time.sleep(8)
                        saved = _try_save_captured()
                        if saved:
                            return saved

                    log.info(f"   [CARSI-Browser] No PDF found. Title: {page.title()[:40]} URL: {page.url[:60]}")
                    return None

            except Exception as e:
                log.info(f"   [CARSI-Browser] Error: {e}")
                return None

    def _find_downloaded_pdf(self, download_dir: str, doi: str) -> Path | None:
        """Check download directory for recently downloaded PDF files."""
        dir_path = Path(download_dir)
        if not dir_path.exists():
            return None
        now = time.time()
        for f in dir_path.iterdir():
            if f.suffix.lower() == ".pdf" and (now - f.stat().st_mtime) < 30:
                try:
                    if f.stat().st_size > 1000:
                        return f
                except OSError:
                    pass
        return None

    def _try_load_cookies(self, publisher: str) -> bool:
        cookie_file = self._cookie_path(publisher)
        if not cookie_file.exists():
            return False
        try:
            cookies = json.loads(cookie_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return False

        sess = self._get_session(publisher)
        for cookie in cookies:
            sess.cookies.set(
                cookie["name"],
                cookie["value"],
                domain=cookie.get("domain", ""),
                path=cookie.get("path", "/"),
            )
        return self._validate_session(publisher)

    def _validate_session(self, publisher: str) -> bool:
        cfg = self._publisher_configs.get(publisher)
        if not cfg:
            return False
        sess = self._get_session(publisher)

        # Optionally apply an age limit, then always validate the live session.
        cookie_file = self._cookie_path(publisher)
        try:
            max_age_hours = int(self.config.get("carsi_cookie_max_age_hours", 0) or 0)
            if max_age_hours > 0:
                age_hours = (time.time() - os.path.getmtime(cookie_file)) / 3600
                if age_hours > max_age_hours:
                    log.info(
                        f"   [CARSI] Cookies for {publisher} exceeded configured age limit "
                        f"({age_hours:.1f}h > {max_age_hours}h)"
                    )
                    return False
        except OSError:
            return False

        # Validate by hitting a publisher page that requires auth
        # Use the main domain, not login_url (which always contains "login")
        try:
            test_url = f"https://{cfg.domains[0]}/"
            resp = sess.get(test_url, timeout=15, allow_redirects=True)
            # If we get redirected to a SSO/CAS/WAYF page, session is invalid
            url_lower = resp.url.lower()
            sso_keywords = ("wayf", "shibboleth", "saml", "idp.bayern", "passport")
            if any(k in url_lower for k in sso_keywords):
                return False
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def _browser_login(self, publisher: str) -> bool:
        """Login via CARSI using CloakBrowser."""
        cfg = self._publisher_configs.get(publisher)
        if not cfg:
            log.error(f"   [CARSI] Unknown publisher: {publisher}")
            return False

        try:
            from ..browser_login import carsi_login
            return carsi_login(publisher, self.config, login_url=cfg.login_url, domains=cfg.domains)
        except Exception as exc:
            log.error(f"   [CARSI] CloakBrowser login failed: {exc}")
            return False

    def _extract_chrome_cookies(self, publisher: str) -> None:
        """Try to extract cookies from Chrome's cookie database."""
        cfg = self._publisher_configs.get(publisher)
        if not cfg:
            return

        cookie_paths = [
            Path.home() / "AppData/Local/Google/Chrome/User Data/Default/Cookies",
            Path.home() / "AppData/Local/Google/Chrome/User Data/Default/Network/Cookies",
        ]

        for cookie_path in cookie_paths:
            if not cookie_path.exists():
                continue
            try:
                import shutil
                import sqlite3
                tmp_cookie = self._cookie_dir / "chrome_cookies_tmp.db"
                shutil.copy2(cookie_path, tmp_cookie)

                conn = sqlite3.connect(str(tmp_cookie))
                cursor = conn.cursor()

                cookies = []
                for domain in cfg.domains:
                    cursor.execute(
                        "SELECT name, value, host_key, path FROM cookies WHERE host_key LIKE ?",
                        (f"%{domain}%",),
                    )
                    cookies.extend(cursor.fetchall())
                conn.close()
                tmp_cookie.unlink(missing_ok=True)

                if cookies:
                    cookie_file = self._cookie_path(publisher)
                    cookie_data = [
                        {"name": n, "value": v, "domain": h, "path": p}
                        for n, v, h, p in cookies
                    ]
                    cookie_file.write_text(
                        json.dumps(cookie_data, indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )
                    log.info(f"   [CARSI] Extracted {len(cookie_data)} cookies from Chrome")
                    return
            except Exception as e:
                log.warning(f"   [CARSI] Chrome cookie extraction failed: {e}")

    def close(self):
        for sess in self._sessions.values():
            sess.close()
        self._sessions.clear()
