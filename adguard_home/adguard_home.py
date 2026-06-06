from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import urllib3

from plugins.base_plugin.base_plugin import BasePlugin
from utils.http_client import get_http_session

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


@dataclass
class EndpointBundle:
    base: str
    auth: Optional[Tuple[str, str]]


class AdGuardHome(BasePlugin):
    """AdGuard Home dashboard optimized for 6-color Waveshare e-paper displays."""

    plugin_name = "AdGuard Home"

    def generate_settings_template(self):
        params = super().generate_settings_template()
        params.update(
            {
                "style_settings": True,
                "supports_preview": True,
                "supports_orientation": True,
            }
        )
        return params

    def generate_image(self, settings, device_config):
        canvas = device_config.get_resolution()
        if device_config.get_config("orientation") == "vertical":
            canvas = canvas[::-1]

        endpoint = self._build_endpoint_bundle(settings)
        snapshot = self._collect_snapshot(endpoint)
        toggles = self._coerce_display_settings(settings)

        template_params = {
            **snapshot,
            **toggles,
            "accent_ok": settings.get("accent_ok", "#008000"),
            "accent_warn": settings.get("accent_warn", "#ff9900"),
            "accent_alert": settings.get("accent_alert", "#ff0000"),
            "accent_info": settings.get("accent_info", "#0000ff"),
            "accent_panel": settings.get("accent_panel", "#000000"),
            "plugin_settings": settings,
        }

        return self.render_image(
            canvas,
            "adguard_home.html",
            "adguard_home.css",
            template_params,
        )

    def _build_endpoint_bundle(self, settings) -> EndpointBundle:
        host = (settings.get("host") or "").strip().rstrip("/")
        user = (settings.get("username") or "").strip()
        password = settings.get("password") or ""
        if not host:
            raise RuntimeError("Set the AdGuard Home host before rendering.")

        auth = (user, password) if user else None
        session = get_http_session()

        probes = [f"{host}/control/", f"{host}/"]
        for candidate in probes:
            try:
                response = session.get(
                    urljoin(candidate, "status"),
                    auth=auth,
                    timeout=10,
                    verify=False,
                )
                if response.status_code in (200, 401):
                    return EndpointBundle(base=candidate.rstrip("/"), auth=auth)
            except Exception as exc:
                log.debug("Probe failed for %s: %s", candidate, exc)

        raise RuntimeError(
            "AdGuard Home API was not found. Try the direct URL or reverse-proxy root."
        )

    def _collect_snapshot(self, endpoint: EndpointBundle) -> Dict[str, Any]:
        session = get_http_session()
        try:
            status = self._api_get(session, endpoint, "status")
            stats = self._api_get(session, endpoint, "stats")
            querylog = (
                self._safe_api_get(session, endpoint, "querylog?limit=6") or {"data": []}
            )
            filtering = (
                self._safe_api_get(session, endpoint, "filtering/status") or {}
            )
            clients = self._safe_api_get(session, endpoint, "clients") or {}
        except Exception as exc:
            log.exception("AdGuard Home fetch failed")
            raise RuntimeError(f"Unable to load AdGuard Home data: {exc}") from exc

        total_queries = int(stats.get("num_dns_queries", 0))
        blocked_queries = int(stats.get("num_blocked_filtering", 0))
        safe_browsing = int(stats.get("num_replaced_safebrowsing", 0))
        safe_search = int(stats.get("num_replaced_safesearch", 0))
        parental = int(stats.get("num_replaced_parental", 0))
        avg_processing_ms = round(
            float(stats.get("avg_processing_time", 0)) * 1000, 2
        )
        blocked_percent = (
            round((blocked_queries / total_queries) * 100, 1) if total_queries else 0.0
        )

        dns_history = list(stats.get("dns_queries", []))[-24:]
        blocked_history = list(stats.get("blocked_filtering", []))[-24:]
        chart_rows = self._build_chart_rows(dns_history, blocked_history)
        top_clients = self._format_top_clients(stats.get("top_clients", []))
        latest_queries = self._format_recent_queries(querylog.get("data", []))
        total_clients = (
            len(clients.get("clients", []))
            if isinstance(clients.get("clients"), list)
            else 0
        )

        protection_enabled = bool(status.get("protection_enabled", False))
        status_level = self._derive_status(protection_enabled, blocked_percent)

        return {
            "protection_enabled": protection_enabled,
            "version": status.get("version", "Unknown"),
            "total_queries": total_queries,
            "blocked_queries": blocked_queries,
            "blocked_percent": blocked_percent,
            "safe_browsing": safe_browsing,
            "safe_search": safe_search,
            "parental": parental,
            "avg_processing_ms": avg_processing_ms,
            "rules_count": int(filtering.get("rules_count", 0)),
            "top_clients": top_clients,
            "latest_queries": latest_queries,
            "chart_rows": chart_rows,
            "query_peak": max(dns_history) if dns_history else 0,
            "total_clients": total_clients,
            "status_level": status_level,
            "privacy_score": self._privacy_score(
                blocked_percent, safe_browsing, safe_search, parental
            ),
        }

    def _api_get(
        self, session, endpoint: EndpointBundle, path: str
    ) -> Dict[str, Any]:
        response = session.get(
            urljoin(endpoint.base + "/", path),
            auth=endpoint.auth,
            timeout=10,
            verify=False,
        )
        response.raise_for_status()
        return response.json()

    def _safe_api_get(
        self, session, endpoint: EndpointBundle, path: str
    ) -> Optional[Dict[str, Any]]:
        try:
            return self._api_get(session, endpoint, path)
        except Exception as exc:
            log.info("Optional endpoint unavailable (%s): %s", path, exc)
            return None

    def _build_chart_rows(
        self, dns_history: List[int], blocked_history: List[int]
    ) -> List[Dict[str, int]]:
        rows: List[Dict[str, int]] = []
        peak = max(dns_history or [1])

        for idx, dns_count in enumerate(dns_history):
            blocked_count = blocked_history[idx] if idx < len(blocked_history) else 0
            ratio = (blocked_count / dns_count) if dns_count else 0
            rows.append(
                {
                    "label": idx,
                    "total_pct": round((dns_count / peak) * 100) if peak else 0,
                    "blocked_pct": round((blocked_count / peak) * 100) if peak else 0,
                    "is_hot": dns_count > 0 and ratio >= 0.35,
                }
            )

        return rows

    def _format_top_clients(
        self, source: List[Dict[str, int]]
    ) -> List[Dict[str, Any]]:
        clients: List[Dict[str, Any]] = []
        for item in source[:5]:
            if isinstance(item, dict) and item:
                name, count = next(iter(item.items()))
                clients.append({"name": str(name)[:22], "count": int(count)})
        return clients

    def _format_recent_queries(
        self, source: List[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        for item in source[:4]:
            rows.append(
                {
                    "host": str(item.get("question", {}).get("name") or "-")[:28],
                    "decision": str(item.get("result", "ok"))
                    .replace("_", " ")
                    .title(),
                    "client": str(item.get("client") or "unknown")[:16],
                }
            )
        return rows

    def _coerce_display_settings(self, settings) -> Dict[str, bool]:
        defaults = {
            "show_status": True,
            "show_totals": True,
            "show_services": True,
            "show_clients": True,
            "show_queries": True,
            "show_chart": True,
        }
        return {
            key: self._to_bool(settings.get(key), default)
            for key, default in defaults.items()
        }

    def _to_bool(self, value: Any, default: bool = False) -> bool:
        if value is None:
            return default

        if isinstance(value, bool):
            return value

        if isinstance(value, (list, tuple)):
            normalized = [str(item).strip().lower() for item in value]
            if any(v in ("true", "1", "yes", "on") for v in normalized):
                return True
            if any(v in ("false", "0", "no", "off", "") for v in normalized):
                return False
            return default

        normalized = str(value).strip().lower()
        if normalized in ("true", "1", "yes", "on"):
            return True
        if normalized in ("false", "0", "no", "off", ""):
            return False
        return default

    def _derive_status(
        self, protection_enabled: bool, blocked_percent: float
    ) -> str:
        if not protection_enabled:
            return "offline"
        if blocked_percent >= 25:
            return "shielding"
        if blocked_percent >= 10:
            return "balanced"
        return "light"

    def _privacy_score(
        self, blocked_percent: float, safe_browsing: int, safe_search: int, parental: int
    ) -> int:
        score = min(
            100,
            int(blocked_percent * 2.2)
            + (8 if safe_browsing else 0)
            + (6 if safe_search else 0)
            + (4 if parental else 0),
        )
        return max(score, 5)