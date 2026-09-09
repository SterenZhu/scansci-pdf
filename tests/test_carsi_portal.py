"""Regression tests for central CARSI portal browser routing."""

from scansci_pdf.config import DEFAULT_CONFIG
from scansci_pdf.sources.carsi import (
    CARSIClient,
    _PORTAL_RESOURCE_URL_JS,
    _canonical_article_url,
    _extract_pii,
    _extract_ieee_article_id,
    _hostname_matches,
    _load_publisher_configs,
)
from scansci_pdf.sources import _build_institutional_sources
from scansci_pdf.fetcher import PaperFetcher
from scansci_pdf.models import Paper


class FakePage:
    def __init__(self, *, evaluated=None, landing_url="https://www.sciencedirect.com/"):
        self._evaluated = evaluated
        self._landing_url = landing_url
        self.url = "about:blank"
        self.goto_calls = []
        self.evaluate_calls = []

    def evaluate(self, script, arg):
        self.evaluate_calls.append((script, arg))
        if isinstance(self._evaluated, list):
            return self._evaluated.pop(0) if self._evaluated else None
        return self._evaluated

    def goto(self, url, **kwargs):
        self.goto_calls.append(url)
        self.url = self._landing_url if "gotoResource" in url else url


def _client(**overrides):
    config = {
        "carsi_portal_url": "https://ds.carsi.edu.cn/resource/resource.php",
        "carsi_portal_timeout": 10,
        **overrides,
    }
    client = object.__new__(CARSIClient)
    client.config = config
    client._publisher_configs = _load_publisher_configs()
    return client


def test_carsi_portal_config_defaults_to_opt_in():
    assert DEFAULT_CONFIG["carsi_portal_url"] == ""
    assert DEFAULT_CONFIG["carsi_portal_timeout"] == 120
    assert DEFAULT_CONFIG["carsi_cookie_max_age_hours"] == 0


def test_portal_terms_cover_supported_publisher_names():
    client = _client()

    assert "ScienceDirect" in client._portal_terms("sciencedirect")
    assert "Elsevier" in client._portal_terms("sciencedirect")
    assert "IEEE Xplore" in client._portal_terms("ieee")
    assert "Springer Nature" in client._portal_terms("springer")


def test_portal_resource_url_accepts_discovered_route_without_resource_id():
    route = "https://ds.carsi.edu.cn/resource/gotoResource.php?id=resource:999"
    page = FakePage(evaluated=route)

    assert _client()._portal_resource_url(page, "sciencedirect") == route


def test_portal_selector_handles_javascript_href_on_detail_page():
    assert "document.location.pathname.includes('resourceDetail')" in _PORTAL_RESOURCE_URL_JS
    assert "`${href} ${onclick}`.match" in _PORTAL_RESOURCE_URL_JS


def test_publisher_landing_does_not_accept_elsevier_auth_intermediate():
    assert _hostname_matches("www.sciencedirect.com", "sciencedirect.com") is True
    assert _hostname_matches("auth.elsevier.com", "sciencedirect.com") is False
    assert _hostname_matches("evilsciencedirect.com", "sciencedirect.com") is False


def test_linkinghub_url_is_canonicalized_before_sciencedirect_navigation():
    assert _canonical_article_url(
        "sciencedirect",
        "https://linkinghub.elsevier.com/retrieve/pii/S138912862500252X",
    ) == "https://www.sciencedirect.com/science/article/pii/S138912862500252X"


def test_pii_survives_when_current_page_redirect_has_no_pii():
    original = "https://linkinghub.elsevier.com/retrieve/pii/S138912862500252X"
    assert _extract_pii("https://www.sciencedirect.com/check") == ""
    assert _extract_pii(original) == "S138912862500252X"


def test_ieee_article_id_is_extracted_for_stamp_url():
    assert _extract_ieee_article_id("https://ieeexplore.ieee.org/document/9019870/") == "9019870"
    assert _extract_ieee_article_id("https://ieeexplore.ieee.org/Xplore/login.jsp") == ""


def test_portal_selector_prioritizes_alias_order():
    assert "for (const term of wanted)" in _PORTAL_RESOURCE_URL_JS
    assert "for (const node of nodes)" in _PORTAL_RESOURCE_URL_JS


def test_ieee_alias_prefers_iel_and_excludes_ieee_wiley():
    client = _client()
    terms = client._portal_terms("ieee")
    assert terms[0] == "IEEE-IET ELECTRONIC LIBRARY"
    assert "ieee-wiley" in _PORTAL_RESOURCE_URL_JS.lower()


def test_ieee_publisher_profile_uses_pdf_endpoint():
    from scansci_pdf.sources.carsi import _load_publisher_configs

    assert _load_publisher_configs()["ieee"].pdf_pattern.startswith("/stampPDF/getPDF.jsp")


def test_authenticated_context_accepts_only_real_pdf_bytes():
    class Response:
        status = 200
        headers = {"content-type": "application/pdf"}

        @staticmethod
        def body():
            return b"%PDF-" + (b"x" * 6000)

    class Request:
        @staticmethod
        def get(url, **kwargs):
            return Response()

    context = type("Context", (), {"request": Request()})()

    result = CARSIClient._context_pdf_request(context, "https://example.test/paper.pdf", "https://example.test/")
    assert result is not None
    assert result.startswith(b"%PDF-")


def test_in_page_pdf_request_decodes_valid_pdf():
    import base64

    body = b"%PDF-" + (b"x" * 6000)

    class Page:
        @staticmethod
        def evaluate(script, url):
            return {
                "status": 200,
                "contentType": "application/pdf",
                "data": base64.b64encode(body).decode("ascii"),
            }

    assert CARSIClient._page_pdf_request(Page(), "https://example.test/paper.pdf") == body


def test_portal_auth_is_not_overwritten_by_cookie_probe_source():
    source = __import__("inspect").getsource(CARSIClient._download_via_cloakbrowser)
    assert "if has_cookies and not needs_login and not portal_authenticated:" in source


def test_sciencedirect_viewer_asset_has_authenticated_context_fallback():
    source = __import__("inspect").getsource(CARSIClient._download_via_cloakbrowser)
    assert '"pdf.sciencedirectassets.com" in current_pdf_url' in source
    assert "self._context_pdf_request(context, current_pdf_url, article_url)" in source


def test_portal_entry_uses_one_portal_route_and_reaches_publisher():
    route = "https://ds.carsi.edu.cn/resource/gotoResource.php?id=resource:999"
    page = FakePage(evaluated=route)

    assert _client()._enter_via_portal(page, "sciencedirect") is True
    assert page.goto_calls == [
        "https://ds.carsi.edu.cn/resource/resource.php",
        route,
    ]


def test_portal_entry_follows_discovered_detail_then_access_route():
    detail = "https://ds.carsi.edu.cn/resource/resourceDetail.php?id=resource:999"
    access = "https://ds.carsi.edu.cn/resource/gotoResource.php?id=resource:999"
    page = FakePage(evaluated=[detail, access])

    assert _client()._enter_via_portal(page, "sciencedirect") is True
    assert page.goto_calls == [
        "https://ds.carsi.edu.cn/resource/resource.php",
        detail,
        access,
    ]


def test_invalid_portal_url_stops_without_navigation():
    page = FakePage(evaluated=None)

    assert _client(carsi_portal_url="javascript:alert(1)")._enter_via_portal(
        page, "sciencedirect"
    ) is False
    assert page.goto_calls == []


def test_portal_login_submits_configured_entity_id_once():
    entity_id = "https://idp.example.edu/idp/shibboleth"
    page = FakePage(evaluated=True)
    page.url = "https://ds.carsi.edu.cn/login/index.html"

    assert _client(carsi_idp_entity_id=entity_id)._start_portal_login(page) is True
    assert len(page.evaluate_calls) == 1
    assert page.evaluate_calls[0][1] == entity_id


def test_portal_login_rejects_non_http_entity_id():
    page = FakePage(evaluated=True)
    page.url = "https://ds.carsi.edu.cn/login/index.html"

    assert _client(carsi_idp_entity_id="javascript:alert(1)")._start_portal_login(page) is False
    assert page.evaluate_calls == []


def test_carsi_only_configuration_schedules_one_browser_route():
    sources = _build_institutional_sources(
        "10.1016/example",
        {"carsi_enabled": True, "carsi_idp_name": "Example University"},
    )

    assert [label for _, label in sources] == ["CARSI"]


def test_carsi_with_bridge_capability_is_not_scheduled_twice():
    sources = _build_institutional_sources(
        "10.1016/example",
        {
            "carsi_enabled": True,
            "carsi_idp_name": "Example University",
            "elsevier_api_key": "configured",
        },
    )

    assert [label for _, label in sources] == ["InstSci"]


def test_single_fetch_uses_portal_browser_without_http_login(monkeypatch):
    calls = []

    class FakeCARSIClient:
        def __init__(self, config):
            pass

        def fetch(self, url):
            raise AssertionError("portal mode must not invoke publisher-side HTTP login")

        def download_via_browser(self, doi, article_url, output_path):
            calls.append((doi, article_url, output_path))
            return {"file": str(output_path)}

    from scansci_pdf.sources import carsi as carsi_module

    monkeypatch.setattr(carsi_module, "CARSIClient", FakeCARSIClient)
    monkeypatch.setattr(PaperFetcher, "_extract_pdf_text", staticmethod(lambda paper, path: None))

    fetcher = object.__new__(PaperFetcher)
    fetcher.config = {
        "carsi_portal_url": "https://ds.carsi.edu.cn/resource/resource.php",
        "output_dir": "D:/Papers",
    }
    fetcher._rate_limit = lambda: None
    paper = Paper(doi="10.1016/example")

    result = fetcher._try_carsi_pdf(
        "10.1016/example",
        "https://linkinghub.elsevier.com/retrieve/pii/EXAMPLE",
        paper,
    )

    assert result is not None
    assert result.source == "carsi"
    assert result.pdf_path.endswith("10.1016_example.pdf")
    assert len(calls) == 1


def test_single_fetch_skips_second_carsi_html_attempt_in_portal_mode(monkeypatch):
    fetcher = object.__new__(PaperFetcher)
    fetcher.config = {"carsi_portal_url": "https://ds.carsi.edu.cn/resource/resource.php"}

    assert fetcher._try_carsi_html("https://example.test/article", Paper()) is None


def test_carsi_only_does_not_claim_webvpn_is_configured():
    fetcher = object.__new__(PaperFetcher)
    fetcher.config = {
        "carsi_enabled": True,
        "carsi_idp_name": "Example University",
        "carsi_portal_url": "https://ds.carsi.edu.cn/resource/resource.php",
    }

    assert fetcher._institution_configured() is True
    assert fetcher._non_carsi_institution_configured() is False
