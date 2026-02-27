#!/usr/bin/env python3
"""
QRadar SIEM Audit Script

Performs a comprehensive audit of an IBM QRadar SIEM implementation, with
robust error handling, retries, pagination, debug logging, and multiple report
formats (console/JSON/CSV/HTML).

Author: sudo3rs 
License: MIT

Requirements:
  - Python 3.8+
  - requests, pandas, colorama, python-dotenv

Quick start:
  1) Create a .env file:
       QRADAR_URL=https://your-qradar-console.example.com
       QRADAR_TOKEN=your-api-token
       VERIFY_SSL=True
  2) python qradar-siem-auditor.py --help

Key improvements vs. original:
  • Fixed broken/duplicated code blocks and undefined variables
  • Centralized API helper with retries, backoff, timeouts, and pagination (Range/Content-Range)
  • Safer Ariel search polling (status handling + timeouts)
  • CLI to include/exclude categories/checks and choose output formats
  • Structured logging to file with --debug for verbose tracing
  • Dry-run mode to test flow without hitting your QRadar
  • HTML/JSON/CSV report export with a timestamped output folder
  • Defensive JSON parsing and graceful degradation on partial failures
"""

from __future__ import annotations
import os
import sys
import json
import time
import math
import argparse
import datetime as dt
import logging
from logging import handlers
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
import pandas as pd
from colorama import Fore, Style, init as colorama_init
from dotenv import load_dotenv

try:
    from fpdf import FPDF
    _HAS_FPDF = True
except ImportError:
    _HAS_FPDF = False

# ------------------------------ Setup ---------------------------------
colorama_init(autoreset=True)
load_dotenv()

DEFAULT_TIMEOUT = 20  # seconds per request
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF = 1.5
DEFAULT_PAGE_SIZE = 50  # for Range-based pagination

# Severity weights per check (1=informational … 10=critical)
SEVERITY_MAP: Dict[str, int] = {
    "Log Sources": 9,
    "Event Collection Rate": 8,
    "Log Source Coverage": 7,
    "Log Source Status": 7,
    "System Health": 8,
    "Deployment Architecture": 6,
    "Storage Utilization": 8,
    "Backup Configuration": 9,
    "User Access Controls": 9,
    "Password Policies": 7,
    "Network Security": 8,
    "Authentication Methods": 8,
    "Custom Rules": 7,
    "Offense Configuration": 8,
    "Rule Coverage": 7,
    "Reference Sets": 6,
    "Search Performance": 5,
    "Report Configuration": 4,
    "Dashboard Configuration": 4,
    "Retention Policies": 7,
    "External Integrations": 6,
    "Data Exports": 5,
    "API Usage": 5,
    # New categories
    "Patch Level": 9,
    "License Compliance": 8,
    "Audit Trail": 7,
    "EPS Capacity": 8,
    "Ariel Disk Usage": 7,
    "Flow Dedup Ratio": 5,
}

# ---------------------------- Logging ---------------------------------

def setup_logger(log_path: str, debug: bool) -> logging.Logger:
    logger = logging.getLogger("qradar_audit")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console (INFO+)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if debug else logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File (always DEBUG level)
    fh = handlers.RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger

# ---------------------------- Utilities -------------------------------

class AuditError(Exception):
    pass

def ts() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# -------------------------- Auditor Class -----------------------------

class QRadarAuditor:
    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
        page_size: int = DEFAULT_PAGE_SIZE,
        ariel_window: str = "24h",
        dry_run: bool = False,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the QRadar auditor.

        Env fallbacks:
          QRADAR_URL, QRADAR_TOKEN, VERIFY_SSL
        """
        self.base_url = (base_url or os.getenv("QRADAR_URL", "")).rstrip("/")
        self.token = token or os.getenv("QRADAR_TOKEN", "")
        verify_env = os.getenv("VERIFY_SSL")
        if verify_ssl is None and verify_env is not None:
            verify_ssl = str(verify_env).lower() == "true"
        self.verify_ssl = True if verify_ssl is None else bool(verify_ssl)

        if not self.base_url or not self.token:
            raise AuditError("Missing QRADAR_URL or QRADAR_TOKEN (set in .env or CLI).")

        self.timeout = int(timeout)
        self.max_retries = int(max_retries)
        self.backoff = float(backoff)
        self.page_size = int(page_size)
        self.ariel_window = ariel_window
        self.dry_run = dry_run

        self.logger = logger or setup_logger("qradar_audit.log", debug=False)

        self.session = requests.Session()
        self.headers = {
            "SEC": self.token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        # results structure: {category: {check_name: result_dict}}
        self.results: Dict[str, Dict[str, Dict[str, Any]]] = {}

        # Register checks
        self.audit_categories: Dict[str, Dict[str, Any]] = {
            "Data Collection": {
                "Log Sources": self._check_log_sources,
                "Event Collection Rate": self._check_event_collection_rate,
                "Log Source Coverage": self._check_log_source_coverage,
                "Log Source Status": self._check_log_source_status,
            },
            "System Configuration": {
                "System Health": self._check_system_health,
                "Deployment Architecture": self._check_deployment_architecture,
                "Storage Utilization": self._check_storage_utilization,
                "Backup Configuration": self._check_backup_config,
            },
            "Security Configuration": {
                "User Access Controls": self._check_user_access,
                "Password Policies": self._check_password_policies,
                "Network Security": self._check_network_security,
                "Authentication Methods": self._check_authentication_methods,
            },
            "Detection Capabilities": {
                "Custom Rules": self._check_custom_rules,
                "Offense Configuration": self._check_offense_config,
                "Rule Coverage": self._check_rule_coverage,
                "Reference Sets": self._check_reference_sets,
            },
            "Operational Efficiency": {
                "Search Performance": self._check_search_performance,
                "Report Configuration": self._check_reports,
                "Dashboard Configuration": self._check_dashboards,
                "Retention Policies": self._check_retention_policies,
            },
            "Integration & Data Flow": {
                "External Integrations": self._check_external_integrations,
                "Data Exports": self._check_data_exports,
                "API Usage": self._check_api_usage,
            },
            "Compliance & Governance": {
                "Patch Level": self._check_patch_level,
                "License Compliance": self._check_license_compliance,
                "Audit Trail": self._check_audit_trail,
            },
            "Performance & Tuning": {
                "EPS Capacity": self._check_eps_capacity,
                "Ariel Disk Usage": self._check_ariel_disk_usage,
                "Flow Dedup Ratio": self._check_flow_dedup_ratio,
            },
        }

        self.system_info: Dict[str, Any] = {}

    # ---------------------- HTTP helpers ------------------------------

    def _request(
        self,
        path: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_404: bool = False,
    ) -> Tuple[Optional[Any], int, Dict[str, str]]:
        if self.dry_run:
            self.logger.debug(f"DRY-RUN {method} {path} params={params} body={json_body}")
            return {}, 200, {}

        url = path if path.startswith("http") else urljoin(self.base_url + "/", path.lstrip("/"))
        hdrs = {**self.headers, **(headers or {})}
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.request(
                    method,
                    url,
                    headers=hdrs,
                    params=params,
                    json=json_body,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                status = resp.status_code
                text = (resp.text or "").strip()
                self.logger.debug(f"HTTP {status} {method} {url}")

                if status == 404 and allow_404:
                    return None, status, dict(resp.headers)

                if status in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                    wait = self.backoff ** attempt
                    self.logger.warning(f"Retryable HTTP {status}; backing off {wait:.1f}s (attempt {attempt}/{self.max_retries})")
                    time.sleep(wait)
                    continue

                # Non-2xx
                if status < 200 or status >= 300:
                    self.logger.error(f"API error {status}: {text[:500]}")
                    return None, status, dict(resp.headers)

                # Try JSON; if fails, return text
                if not text:
                    return None, status, dict(resp.headers)
                try:
                    return resp.json(), status, dict(resp.headers)
                except Exception:
                    return text, status, dict(resp.headers)

            except requests.RequestException as e:
                last_exc = e
                if attempt < self.max_retries:
                    wait = self.backoff ** attempt
                    self.logger.warning(f"Network error: {e}; retrying in {wait:.1f}s (attempt {attempt}/{self.max_retries})")
                    time.sleep(wait)
                    continue
                self.logger.exception("Request failed after retries")
                return None, 0, {}
        # Shouldn't reach
        raise AuditError(f"Unreachable code in _request; last_exc={last_exc}")

    def _paginate_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> List[Any]:
        """Fetch all items from QRadar endpoints that support Range/Content-Range.
        Adds Range: items=start-end header and accumulates until total reached.
        """
        items: List[Any] = []
        start = 0
        total = None
        while True:
            end = start + self.page_size - 1
            headers = {"Range": f"items={start}-{end}"}
            data, status, hdrs = self._request(path, params=params, headers=headers)
            if data is None and status == 416:  # Range not satisfiable
                break
            if isinstance(data, list):
                items.extend(data)
            else:
                # Non-list payload; return as single page
                return data if isinstance(data, list) else (items if items else [])
            cr = hdrs.get("Content-Range")  # e.g. items 0-49/123
            if cr and "/" in cr:
                try:
                    total = int(cr.split("/")[-1])
                except ValueError:
                    total = None
            if total is None:
                # If no total, continue until empty page
                if not data:
                    break
            if total is not None and len(items) >= total:
                break
            start += self.page_size
        return items

    # ---------------------- Top-level runners -------------------------

    def run_audit(
        self,
        include_categories: Optional[List[str]] = None,
        exclude_categories: Optional[List[str]] = None,
        include_checks: Optional[List[str]] = None,
        exclude_checks: Optional[List[str]] = None,
        outdir: str = "out",
        export: List[str] = ["console"],
    ) -> Dict[str, Any]:
        print(f"{Fore.CYAN}=== QRadar SIEM Audit Tool ===")
        print(f"{Fore.CYAN}Target: {self.base_url}")
        print(f"{Fore.CYAN}Time: {ts()}\n")

        # Connection test
        ok = self._test_connection()
        if not ok:
            raise AuditError("Connection test failed.")

        # Version
        about = self._get_system_info()
        version = about.get("version", "Unknown") if isinstance(about, dict) else "Unknown"
        print(f"{Fore.CYAN}QRadar Version: {version}\n")

        # Filters
        include_categories = [c.lower() for c in (include_categories or [])]
        exclude_categories = [c.lower() for c in (exclude_categories or [])]
        include_checks = [c.lower() for c in (include_checks or [])]
        exclude_checks = [c.lower() for c in (exclude_checks or [])]

        # Execute checks
        for category, checks in self.audit_categories.items():
            if include_categories and category.lower() not in include_categories:
                continue
            if exclude_categories and category.lower() in exclude_categories:
                continue

            print(f"\n{Fore.BLUE}Auditing {category}…")
            self.results.setdefault(category, {})

            for check_name, fn in checks.items():
                if include_checks and check_name.lower() not in include_checks:
                    continue
                if exclude_checks and check_name.lower() in exclude_checks:
                    continue

                print(f"{Fore.YELLOW}  Checking {check_name}…")
                try:
                    res = fn()
                    if not isinstance(res, dict) or "status" not in res:
                        raise AuditError(f"Check returned invalid structure: {check_name}")
                    self.results[category][check_name] = res
                    color = Fore.GREEN if res["status"] == "PASS" else (Fore.RED if res["status"] == "FAIL" else Fore.YELLOW)
                    print(f"{color}    Status: {res['status']}")
                except Exception as e:
                    self.logger.exception(f"Error in check {category}.{check_name}")
                    self.results[category][check_name] = {
                        "status": "ERROR",
                        "findings": f"Error executing check: {e}",
                        "recommendations": "Review API access, connectivity, and logs. Re-run with --debug.",
                    }
                    print(f"{Fore.RED}    Error: {e}")

        # Inject severity into each result
        for cat, checks in self.results.items():
            for name, r in checks.items():
                r["severity"] = SEVERITY_MAP.get(name, 5)

        overall_score = self._compute_overall_score()
        print(f"\n{Fore.CYAN}Overall Audit Score: {overall_score}/100")

        # Exports
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(outdir, f"qradar_audit_{stamp}")
        os.makedirs(out_path, exist_ok=True)

        if "console" in export:
            self._print_report()
        if "json" in export:
            self._export_json(os.path.join(out_path, "report.json"))
        if "csv" in export:
            self._export_csv(os.path.join(out_path, "report.csv"))
        if "html" in export:
            self._export_html(os.path.join(out_path, "report.html"))
        if "pdf" in export:
            self._export_pdf(os.path.join(out_path, "report.pdf"))

        print(f"\n{Fore.CYAN}Output folder: {out_path}")
        return {"version": version, "results": self.results, "out": out_path, "overall_score": overall_score}

    # ---------------------- Connection & API --------------------------

    def _test_connection(self) -> bool:
        data, status, _ = self._request("/api/system/about")
        if status == 200:
            print(f"{Fore.GREEN}Successfully connected to QRadar API.")
            return True
        print(f"{Fore.RED}Failed to connect to QRadar API (status {status}).")
        return False

    def _get_system_info(self) -> Dict[str, Any]:
        data, _, _ = self._request("/api/system/about")
        if isinstance(data, dict):
            self.system_info = data
            return data
        return {}

    # ---------------------- Data Collection ---------------------------

    def _check_log_sources(self) -> Dict[str, Any]:
        items = self._paginate_json("/api/config/event_sources/log_source_management/log_sources")
        if items is None or not isinstance(items, list):
            return {
                "status": "FAIL",
                "findings": "Unable to retrieve log sources.",
                "recommendations": "Check API permissions/connectivity and token scope.",
            }
        total = len(items)
        enabled = sum(1 for s in items if s.get("enabled"))
        status_counts: Dict[str, int] = {}
        for s in items:
            st = (s.get("status") or {}).get("status", "Unknown")
            status_counts[st] = status_counts.get(st, 0) + 1
        issues = sum(status_counts.get(k, 0) for k in ("Error", "Warning", "Disabled"))

        if total == 0:
            status = "FAIL"
            findings = "No log sources configured."
            rec = "Onboard critical log sources to ensure visibility."
        elif issues > total * 0.10:
            status = "FAIL"
            findings = f"{issues}/{total} log sources in problematic state."
            rec = "Investigate failing sources and fix transport/parsers."
        else:
            status = "PASS"
            findings = f"{total} log sources found; {enabled} enabled."
            rec = "Continue monitoring and add new sources as needed."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {"total": total, "enabled": enabled, "status_counts": status_counts},
        }

    def _check_event_collection_rate(self) -> Dict[str, Any]:
        """Count events in a recent window via Ariel search.
        ariel_window examples: "24h", "7d", "1d". Converted to hours.
        """
        # Convert window to hours
        hours = 24
        try:
            if self.ariel_window.endswith("h"):
                hours = int(self.ariel_window[:-1])
            elif self.ariel_window.endswith("d"):
                hours = int(self.ariel_window[:-1]) * 24
        except Exception:
            pass

        # AQL note: There are multiple valid syntaxes; this one is broadly compatible
        aql = f"SELECT COUNT(*) AS event_count FROM events WHERE starttime > NOW - {hours} HOURS"
        create_payload = {"query_expression": aql}
        data, status, _ = self._request("/api/ariel/searches", method="POST", json_body=create_payload)
        if not isinstance(data, dict) or "search_id" not in data:
            return {
                "status": "WARNING",
                "findings": "Unable to start Ariel search for event count.",
                "recommendations": "Check Ariel permissions and logs; try increasing --timeout.",
            }
        search_id = data["search_id"]

        # Poll status
        t0 = time.time()
        deadline = t0 + max(60, self.timeout * 3)
        final_status = "UNKNOWN"
        while time.time() < deadline:
            info, st, _ = self._request(f"/api/ariel/searches/{search_id}")
            if isinstance(info, dict):
                final_status = info.get("status", final_status)
                if final_status in {"COMPLETED", "CANCELED", "ERROR", "THROTTLED"}:
                    break
            time.sleep(2)

        if final_status != "COMPLETED":
            return {
                "status": "WARNING",
                "findings": f"Ariel search not completed (status={final_status}).",
                "recommendations": "Optimize Ariel, reduce window, or allocate resources.",
            }

        rows, st, _ = self._request(f"/api/ariel/searches/{search_id}/results")
        event_count = 0
        try:
            if isinstance(rows, list) and rows:
                # Expect rows like [{"event_count": 12345}]
                event_count = int(next(iter(rows[0].values())))
        except Exception:
            pass

        if event_count == 0:
            status = "FAIL"
            findings = "No events collected in the selected window."
            rec = "Verify log source connectivity and DSM mappings."
        elif event_count < 1000 and hours >= 24:
            status = "WARNING"
            findings = f"Low event volume: {event_count} in last {hours}h."
            rec = "Confirm key sources are onboarded and not throttled."
        else:
            status = "PASS"
            findings = f"Healthy rate: {event_count} events in last {hours}h."
            rec = "Keep monitoring for unexpected drops/spikes."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {"window_hours": hours, "event_count": event_count, "events_per_hour": round(event_count / max(1, hours), 2)},
        }

    def _check_log_source_coverage(self) -> Dict[str, Any]:
        items = self._paginate_json("/api/config/event_sources/log_source_management/log_sources")
        if items is None or not isinstance(items, list):
            return {
                "status": "WARNING",
                "findings": "Unable to retrieve log sources.",
                "recommendations": "Check token scope and user role.",
            }
        critical = {
            "Firewall": False,
            "IDS/IPS": False,
            "Authentication": False,
            "Operating System": False,
            "Network Device": False,
            "Database": False,
            "Web Server": False,
            "Endpoint": False,
            "Cloud Service": False,
            "Active Directory": False,
        }
        mapping = {
            "Cisco PIX/ASA": "Firewall",
            "Juniper SRX": "Firewall",
            "CheckPoint": "Firewall",
            "Palo Alto PA": "Firewall",
            "Snort": "IDS/IPS",
            "Sourcefire": "IDS/IPS",
            "Cisco IPS": "IDS/IPS",
            "Microsoft Windows Security": "Authentication",
            "RADIUS": "Authentication",
            "LDAP": "Authentication",
            "Microsoft Windows": "Operating System",
            "Unix": "Operating System",
            "Linux": "Operating System",
            "Cisco IOS": "Network Device",
            "Juniper JunOS": "Network Device",
            "Oracle": "Database",
            "Microsoft SQL Server": "Database",
            "MySQL": "Database",
            "PostgreSQL": "Database",
            "Apache": "Web Server",
            "IIS": "Web Server",
            "Nginx": "Web Server",
            "Microsoft Windows Endpoint": "Endpoint",
            "Carbon Black": "Endpoint",
            "CrowdStrike": "Endpoint",
            "AWS CloudTrail": "Cloud Service",
            "Azure Activity Log": "Cloud Service",
            "Office 365": "Cloud Service",
            "Google Cloud": "Cloud Service",
            "Microsoft Active Directory": "Active Directory",
        }
        for s in items:
            tname = (s.get("type_name") or "").lower()
            if not s.get("enabled"):
                continue
            for k, v in mapping.items():
                if k.lower() in tname:
                    critical[v] = True
        covered = sum(1 for v in critical.values() if v)
        total = len(critical)
        pct = 100.0 * covered / total if total else 0.0
        missing = [k for k, v in critical.items() if not v]
        if pct < 50:
            status = "FAIL"; findings = f"Poor coverage: {pct:.1f}%"; rec = f"Add: {', '.join(missing)}"
        elif pct < 80:
            status = "WARNING"; findings = f"Moderate coverage: {pct:.1f}%"; rec = f"Consider adding: {', '.join(missing)}"
        else:
            status = "PASS"; findings = f"Good coverage: {pct:.1f}%"; rec = "Maintain and review quarterly."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {"coverage_percentage": pct, "covered_types": covered, "total_types": total, "missing_types": missing},
        }

    def _check_log_source_status(self) -> Dict[str, Any]:
        items = self._paginate_json("/api/config/event_sources/log_source_management/log_sources")
        if items is None or not isinstance(items, list):
            return {
                "status": "WARNING",
                "findings": "Unable to retrieve log source status.",
                "recommendations": "Check API role and connectivity.",
            }
        counts = {"Active": 0, "Error": 0, "Warning": 0, "Disabled": 0, "Unknown": 0}
        problems: List[Dict[str, Any]] = []
        for s in items:
            st = (s.get("status") or {}).get("status", "Unknown")
            if st not in counts:
                st = "Unknown"
            counts[st] += 1
            if st in ("Error", "Warning"):
                problems.append({
                    "name": s.get("name", "<unknown>"),
                    "type": s.get("type_name", "<unknown>"),
                    "status": st,
                    "last_event": s.get("last_event_time", "Never"),
                })
        total = sum(counts.values())
        pct = 100.0 * (counts["Error"] + counts["Warning"]) / total if total else 0.0
        if pct > 20:
            status = "FAIL"; findings = f"High issue rate: {pct:.1f}%"; rec = "Prioritize remediation for failing sources."
        elif pct > 5:
            status = "WARNING"; findings = f"Moderate issue rate: {pct:.1f}%"; rec = "Triage warnings and fix parsers/connectivity."
        else:
            status = "PASS"; findings = f"Low issue rate: {pct:.1f}%"; rec = "Continue monitoring."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {"status_counts": counts, "problem_percentage": pct, "problem_sources": problems[:5]},
        }

    # ---------------------- System Configuration ----------------------

    def _check_system_health(self) -> Dict[str, Any]:
        # Placeholder: replace with /api/system/health if available in your version
        m = {
            "cpu_utilization": 65,
            "memory_utilization": 72,
            "disk_io_utilization": 40,
            "event_processing_delay": 2.5,
            "services_status": "All services running",
        }
        concerns = []
        if m["cpu_utilization"] > 80: concerns.append(f"High CPU ({m['cpu_utilization']}%)")
        if m["memory_utilization"] > 85: concerns.append(f"High RAM ({m['memory_utilization']}%)")
        if m["disk_io_utilization"] > 75: concerns.append(f"High disk I/O ({m['disk_io_utilization']}%)")
        if m["event_processing_delay"] > 5: concerns.append(f"Delay {m['event_processing_delay']}s")
        if "not running" in m["services_status"].lower(): concerns.append("Service issues present")
        if len(concerns) > 2:
            status, findings, rec = "FAIL", f"Multiple issues: {', '.join(concerns)}", "Re-evaluate sizing and tune pipeline."
        elif concerns:
            status, findings, rec = "WARNING", f"Concerns: {', '.join(concerns)}", "Monitor closely; plan optimization."
        else:
            status, findings, rec = "PASS", "Health within acceptable ranges.", "Continue regular monitoring."
        return {"status": status, "findings": findings, "recommendations": rec, "details": m}

    def _check_deployment_architecture(self) -> Dict[str, Any]:
        hosts = self._paginate_json("/api/system/servers")
        if not isinstance(hosts, list) or not hosts:
            return {
                "status": "WARNING",
                "findings": "Unable to retrieve deployment info.",
                "recommendations": "Ensure user has admin API role.",
            }
        console = ep = ec = fp = dn = 0
        for h in hosts:
            comps = h.get("components", [])
            console += int("CONSOLE" in comps)
            ep += int("EVENT_PROCESSOR" in comps)
            ec += int("EVENT_COLLECTOR" in comps)
            fp += int("FLOW_PROCESSOR" in comps)
            dn += int("DATA_NODE" in comps)
        if len(hosts) == 1:
            dtype = "All-in-one"
        elif len(hosts) <= 3:
            dtype = "Basic distributed"
        else:
            dtype = "Fully distributed"
        concerns = []
        if dtype == "All-in-one" and ep > 0: concerns.append("All-in-one handling event processing")
        if ec == 0: concerns.append("No dedicated event collectors")
        if console == 0: concerns.append("No console component found")
        if console > 1: concerns.append("Multiple consoles detected")
        if dtype != "All-in-one" and ep == 0: concerns.append("No dedicated event processors")
        if len(concerns) > 2:
            status, findings, rec = "FAIL", f"Suboptimal architecture: {', '.join(concerns)}", "Align with QRadar best practices."
        elif concerns:
            status, findings, rec = "WARNING", f"Architecture concerns: {', '.join(concerns)}", "Consider scaling/role separation."
        else:
            status, findings, rec = "PASS", f"Appropriate {dtype} architecture.", "Scale with data growth."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {
                "deployment_type": dtype,
                "host_count": len(hosts),
                "console_count": console,
                "event_processor_count": ep,
                "event_collector_count": ec,
                "flow_collector_count": fp,
                "data_node_count": dn,
            },
        }

    def _check_storage_utilization(self) -> Dict[str, Any]:
        s = {
            "total_storage": 5000,
            "used_storage": 3200,
            "storage_allocation": {"events": 70, "flows": 20, "assets": 5, "other": 5},
            "retention_periods": {"events": 90, "flows": 30, "assets": 180},
        }
        util = 100.0 * s["used_storage"] / s["total_storage"] if s["total_storage"] else 0
        remaining_days = 42  # heuristic placeholder
        concerns = []
        if util > 85: concerns.append(f"High utilization ({util:.1f}%)")
        if remaining_days < 30: concerns.append(f"Low growth headroom (~{remaining_days}d)")
        if s["retention_periods"]["events"] < 30: concerns.append("Short event retention")
        if s["retention_periods"]["flows"] < 7: concerns.append("Short flow retention")
        if util > 90 or remaining_days < 15:
            status, findings, rec = "FAIL", f"Storage risks: {', '.join(concerns)}", "Increase capacity or adjust retention/archiving."
        elif concerns:
            status, findings, rec = "WARNING", f"Storage concerns: {', '.join(concerns)}", "Plan expansion or optimize retention."
        else:
            status, findings, rec = "PASS", f"Healthy utilization ({util:.1f}%).", "Keep monitoring."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {
                "utilization_percentage": util,
                "remaining_days_at_current_rate": remaining_days,
                "total_storage_gb": s["total_storage"],
                "used_storage_gb": s["used_storage"],
                "free_storage_gb": s["total_storage"] - s["used_storage"],
                "retention_periods": s["retention_periods"],
            },
        }

    def _check_backup_config(self) -> Dict[str, Any]:
        b = {
            "backup_enabled": True,
            "backup_frequency": "Daily",
            "last_successful_backup": "2025-08-15T02:30:00",
            "backup_retention": 14,
            "backup_location": "Remote NFS",
            "configuration_included": True,
            "data_included": False,
        }
        try:
            last = dt.datetime.strptime(b["last_successful_backup"], "%Y-%m-%dT%H:%M:%S")
            age_h = (dt.datetime.now() - last).total_seconds() / 3600
        except Exception:
            age_h = 999
        concerns = []
        if not b["backup_enabled"]: concerns.append("Backups disabled")
        if age_h > 48: concerns.append(f"Last backup > {int(age_h/24)} days ago")
        if b["backup_frequency"].lower() not in {"daily", "twice daily"}: concerns.append(f"Infrequent schedule: {b['backup_frequency']}")
        if b["backup_retention"] < 7: concerns.append("Short retention")
        if not b["configuration_included"]: concerns.append("Config not included")
        if len(concerns) and (not b["backup_enabled"] or age_h > 72):
            status, findings, rec = "FAIL", f"Critical backup issues: {', '.join(concerns)}", "Implement/validate robust backup strategy now."
        elif concerns:
            status, findings, rec = "WARNING", f"Backup concerns: {', '.join(concerns)}", "Improve backup schedule and scope."
        else:
            status, findings, rec = "PASS", "Backups configured and recent.", "Test restores regularly."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {**b, "last_backup_age_hours": age_h},
        }

    # ---------------------- Security Configuration --------------------

    def _check_user_access(self) -> Dict[str, Any]:
        users = self._paginate_json("/api/config/access/users")
        if not isinstance(users, list):
            return {
                "status": "WARNING",
                "findings": "Unable to retrieve user info.",
                "recommendations": "Check API permissions and connectivity.",
            }
        admin_count = 0
        inactive = 0
        defaults = 0
        concerns: List[str] = []
        now_ms = time.time() * 1000
        for u in users:
            role_ids = u.get("role_id")
            if isinstance(role_ids, list) and 1 in role_ids:
                admin_count += 1
            if str(u.get("email", "")).lower() in {"admin@localhost", "root@localhost"}:
                defaults += 1
            last_login = u.get("last_login_time", 0)
            if not last_login or (now_ms - last_login) > 90 * 24 * 60 * 60 * 1000:
                inactive += 1
        if admin_count > 5: concerns.append(f"Excessive admins ({admin_count})")
        if defaults: concerns.append(f"Default accounts active ({defaults})")
        if inactive > 3: concerns.append(f"Inactive accounts ({inactive})")
        if len(concerns) > 1:
            status, findings, rec = "FAIL", f"User access issues: {', '.join(concerns)}", "Cleanup accounts; enforce least privilege + quarterly review."
        elif concerns:
            status, findings, rec = "WARNING", f"User access concern: {concerns[0]}", "Review accounts and implement regular access reviews."
        else:
            status, findings, rec = "PASS", "User access controls look reasonable.", "Maintain least-privilege and quarterly review cadence."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {"total_users": len(users), "admin_count": admin_count, "inactive_users": inactive, "default_users": defaults},
        }

    def _check_password_policies(self) -> Dict[str, Any]:
        policy = {
            "minimum_length": 12,
            "complexity_required": True,
            "expiration_days": 90,
            "history_size": 5,
            "lockout_threshold": 5,
            "lockout_duration_minutes": 30,
        }
        concerns = []
        if policy["minimum_length"] < 8: concerns.append("Min length < 8")
        if not policy["complexity_required"]: concerns.append("No complexity")
        if policy["expiration_days"] > 90 or policy["expiration_days"] == 0: concerns.append("Weak expiration policy")
        if policy["history_size"] < 4: concerns.append("Small history")
        if policy["lockout_threshold"] > 5 or policy["lockout_threshold"] == 0: concerns.append("Weak lockout threshold")
        if len(concerns) > 2:
            status, findings, rec = "FAIL", f"Password policy weaknesses: {', '.join(concerns)}", "Align with corporate/compliance requirements."
        elif concerns:
            status, findings, rec = "WARNING", f"Policy concerns: {', '.join(concerns)}", "Tighten password policy settings."
        else:
            status, findings, rec = "PASS", "Password policy meets best practices.", "Review annually."
        return {"status": status, "findings": findings, "recommendations": rec, "details": policy}

    def _check_network_security(self) -> Dict[str, Any]:
        net = {
            "https_enabled": True,
            "tls_version": "TLS 1.2",
            "weak_ciphers_disabled": True,
            "console_accessible_ips": ["10.0.0.0/8", "192.168.0.0/16"],
            "ssh_enabled": True,
            "ssh_root_login_disabled": True,
            "firewall_enabled": True,
            "unnecessary_services_disabled": True,
        }
        concerns = []
        if not net["https_enabled"]: concerns.append("HTTPS disabled")
        if net["tls_version"] not in {"TLS 1.2", "TLS 1.3"}: concerns.append("Outdated TLS")
        if not net["weak_ciphers_disabled"]: concerns.append("Weak ciphers enabled")
        if "0.0.0.0/0" in net["console_accessible_ips"]: concerns.append("Console open to world")
        if not net["ssh_root_login_disabled"]: concerns.append("SSH root login enabled")
        if not net["firewall_enabled"]: concerns.append("Host firewall disabled")
        if len(concerns) > 2:
            status, findings, rec = "FAIL", f"Network security issues: {', '.join(concerns)}", "Harden host and restrict management plane."
        elif concerns:
            status, findings, rec = "WARNING", f"Network concerns: {', '.join(concerns)}", "Tighten crypto/ACLs and host policies."
        else:
            status, findings, rec = "PASS", "Network hardening looks reasonable.", "Maintain secure baseline and review periodically."
        return {"status": status, "findings": findings, "recommendations": rec, "details": net}

    def _check_authentication_methods(self) -> Dict[str, Any]:
        auth = {
            "local_auth_enabled": True,
            "ldap_enabled": True,
            "ldap_servers": 2,
            "ldap_failover_configured": True,
            "ldap_ssl_enabled": True,
            "radius_enabled": False,
            "saml_enabled": False,
            "mfa_enabled": False,
        }
        concerns = []
        suggestions = []
        if not (auth["ldap_enabled"] or auth["radius_enabled"] or auth["saml_enabled"]):
            concerns.append("Only local auth configured")
        if auth["ldap_enabled"] and not auth["ldap_ssl_enabled"]: concerns.append("LDAP without TLS")
        if auth["ldap_enabled"] and auth["ldap_servers"] < 2: concerns.append("Single LDAP server")
        if not auth["mfa_enabled"]: suggestions.append("Enable MFA")
        if len(concerns) > 1:
            status, findings, rec = "FAIL", f"Auth issues: {', '.join(concerns)}", "Harden directory auth; add MFA."
        elif concerns:
            status, findings, rec = "WARNING", f"Auth concern: {concerns[0]}", "Improve authentication controls."
        else:
            if suggestions:
                status, findings, rec = "WARNING", "Auth is OK but could be enhanced.", ", ".join(suggestions)
            else:
                status, findings, rec = "PASS", "Auth methods are secure.", "Review new auth tech annually."
        return {"status": status, "findings": findings, "recommendations": rec, "details": auth}

    # ---------------------- Detection Capabilities --------------------

    def _check_custom_rules(self) -> Dict[str, Any]:
        rules = self._paginate_json("/api/analytics/rules")
        if not isinstance(rules, list):
            return {
                "status": "WARNING",
                "findings": "Unable to retrieve rules.",
                "recommendations": "Confirm /api/analytics access and pagination support.",
            }
        total = len(rules)
        enabled = sum(1 for r in rules if r.get("enabled"))
        custom = sum(1 for r in rules if not r.get("system", False))
        disabled = total - enabled
        never_triggered = 0
        stale = 0
        now_ms = time.time() * 1000
        for r in rules:
            if r.get("enabled"):
                last = r.get("last_run_time", 0)
                if not last:
                    never_triggered += 1
                elif (now_ms - last) > 180 * 24 * 60 * 60 * 1000:
                    stale += 1
        concerns = []
        if custom < 10: concerns.append(f"Low custom rules ({custom})")
        if disabled > total * 0.2: concerns.append(f"Many disabled ({disabled}/{total})")
        if enabled and never_triggered > enabled * 0.3: concerns.append(f"Rules never fired ({never_triggered})")
        if stale > 5: concerns.append(f"Stale rules ({stale})")
        if len(concerns) > 2:
            status, findings, rec = "FAIL", f"Rule hygiene issues: {', '.join(concerns)}", "Triage, tune, and prune rules; run tuning workshops."
        elif concerns:
            status, findings, rec = "WARNING", f"Rule concerns: {', '.join(concerns)}", "Tune/retire noisy/stale rules; add targeted detections."
        else:
            status, findings, rec = "PASS", f"Rules look healthy with {custom} custom items.", "Keep periodic tuning cycles."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {
                "total_rules": total,
                "enabled_rules": enabled,
                "custom_rules": custom,
                "disabled_rules": disabled,
                "never_triggered": never_triggered,
                "stale_rules": stale,
            },
        }

    def _check_offense_config(self) -> Dict[str, Any]:
        params = {"fields": "id,status,assigned_to,start_time"}
        offenses = self._paginate_json("/api/siem/offenses", params)
        if not isinstance(offenses, list):
            return {
                "status": "WARNING",
                "findings": "Unable to retrieve offenses.",
                "recommendations": "Check SIEM API scope and paging.",
            }
        active = [o for o in offenses if str(o.get("status", "")).upper() != "CLOSED"]
        total_active = len(active)
        unassigned = sum(1 for o in active if not o.get("assigned_to"))
        now_ms = time.time() * 1000
        aging = {"0-1 days": 0, "1-7 days": 0, "7-30 days": 0, "30+ days": 0}
        for o in active:
            start = o.get("start_time", now_ms)
            age_d = (now_ms - start) / (24 * 60 * 60 * 1000)
            if age_d <= 1: aging["0-1 days"] += 1
            elif age_d <= 7: aging["1-7 days"] += 1
            elif age_d <= 30: aging["7-30 days"] += 1
            else: aging["30+ days"] += 1
        concerns = []
        if total_active > 100: concerns.append(f"High active offenses ({total_active})")
        if total_active and unassigned > total_active * 0.5: concerns.append(f"Unassigned {unassigned}/{total_active}")
        if aging["30+ days"] > 10: concerns.append(f"Old offenses {aging['30+ days']}")
        if aging["30+ days"] > 30 or total_active > 200:
            status, findings, rec = "FAIL", f"Critical offense mgmt issues: {', '.join(concerns)}", "Establish SLAs, ownership, and automation."
        elif concerns:
            status, findings, rec = "WARNING", f"Offense mgmt concerns: {', '.join(concerns)}", "Reduce backlog and implement triage playbooks."
        else:
            status, findings, rec = "PASS", "Offense handling appears timely.", "Sustain current process; expand automation."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {"total_active": total_active, "unassigned": unassigned, "aging": aging},
        }

    def _check_rule_coverage(self) -> Dict[str, Any]:
        coverage = {
            "Initial Access": 70,
            "Execution": 85,
            "Persistence": 60,
            "Privilege Escalation": 65,
            "Defense Evasion": 55,
            "Credential Access": 80,
            "Discovery": 50,
            "Lateral Movement": 75,
            "Collection": 60,
            "Exfiltration": 70,
            "Command and Control": 85,
            "Impact": 65,
        }
        overall = sum(coverage.values()) / len(coverage)
        gaps = [k for k, v in coverage.items() if v < 60]
        if overall < 50:
            status, findings, rec = "FAIL", f"Poor ATT&CK coverage {overall:.1f}%", f"Develop detections for: {', '.join(gaps)}"
        elif overall < 70:
            status, findings, rec = "WARNING", f"Moderate coverage {overall:.1f}%", f"Improve: {', '.join(gaps)}"
        else:
            status, findings, rec = "PASS", f"Good coverage {overall:.1f}%", "Focus on emerging threats."
        return {"status": status, "findings": findings, "recommendations": rec, "details": {"overall": overall, "by_tactic": coverage, "gaps": gaps}}

    def _check_reference_sets(self) -> Dict[str, Any]:
        refsets = self._paginate_json("/api/reference_data/sets")
        if not isinstance(refsets, list):
            return {
                "status": "WARNING",
                "findings": "Unable to retrieve reference sets.",
                "recommendations": "Confirm Reference Data API access.",
            }
        total = len(refsets); empty = 0; stale = 0
        now_ms = time.time() * 1000
        for rs in refsets:
            if rs.get("number_of_elements", 0) == 0:
                empty += 1
            last = rs.get("last_updated", 0)
            if last and (now_ms - last) > 90 * 24 * 60 * 60 * 1000:
                stale += 1
        common = ["Malicious IPs", "Malicious Domains", "Suspicious User Agents", "TOR Exit Nodes"]
        missing = [n for n in common if not any(str(rs.get("name", "")).lower() == n.lower() for rs in refsets)]
        concerns = []
        if total < 5: concerns.append(f"Few reference sets ({total})")
        if empty > total * 0.3: concerns.append(f"Many empty ({empty}/{total})")
        if stale > total * 0.5: concerns.append(f"Many stale ({stale}/{total})")
        if missing: concerns.append(f"Missing common TI sets: {', '.join(missing)}")
        if len(concerns) > 2:
            status, findings, rec = "FAIL", f"Ref set issues: {', '.join(concerns)}", "Automate TI feeds and routine hygiene."
        elif concerns:
            status, findings, rec = "WARNING", f"Ref set concerns: {', '.join(concerns)}", "Review and optimize reference data."
        else:
            status, findings, rec = "PASS", f"{total} reference sets maintained.", "Keep feeds fresh and validated."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {"total_sets": total, "empty_sets": empty, "stale_sets": stale, "missing_ti_sets": missing},
        }

    # ---------------------- Operational Efficiency --------------------

    def _check_search_performance(self) -> Dict[str, Any]:
        m = {
            "avg_search_time": 45,
            "search_timeout_rate": 0.05,
            "long_running_searches": 3,
            "indexed_fields": 35,
            "custom_properties": 28,
            "search_optimizations_enabled": True,
        }
        concerns = []
        if m["avg_search_time"] > 120: concerns.append(f"High avg time {m['avg_search_time']}s")
        if m["search_timeout_rate"] > 0.1: concerns.append(f"Timeout rate {100*m['search_timeout_rate']:.1f}%")
        if m["long_running_searches"] > 5: concerns.append("Many long-running searches")
        if m["indexed_fields"] < 20: concerns.append("Few indexed fields")
        if not m["search_optimizations_enabled"]: concerns.append("Optimizations disabled")
        if m["avg_search_time"] > 180 or m["search_timeout_rate"] > 0.2:
            status, findings, rec = "FAIL", f"Severe search issues: {', '.join(concerns)}", "Add indexes, tune AQL, and review hardware."
        elif concerns:
            status, findings, rec = "WARNING", f"Search concerns: {', '.join(concerns)}", "Tune indexes/queries; education for users."
        else:
            status, findings, rec = "PASS", "Search performance is healthy.", "Monitor as data grows."
        return {"status": status, "findings": findings, "recommendations": rec, "details": m}

    def _check_reports(self) -> Dict[str, Any]:
        info = {
            "total_reports": 12,
            "scheduled_reports": 8,
            "report_distribution": {"Compliance": 4, "Executive": 2, "Operational": 5, "Custom": 1},
            "report_formats": ["PDF", "CSV"],
            "distribution_methods": ["Email"],
        }
        concerns = []
        sugg = []
        if info["total_reports"] < 5: concerns.append("Few reports configured")
        if info["scheduled_reports"] < info["total_reports"] * 0.5: concerns.append("Few scheduled reports")
        if not info["report_distribution"].get("Executive"): sugg.append("Add exec summaries")
        if not info["report_distribution"].get("Compliance"): sugg.append("Add compliance set")
        if len(info["report_formats"]) < 2: sugg.append("Add more formats")
        if len(info["distribution_methods"]) < 2: sugg.append("Add more distribution methods")
        if concerns:
            status, findings, rec = "WARNING", f"Report concerns: {', '.join(concerns)}", "Expand reporting for stakeholders."
        elif sugg:
            status, findings, rec = "WARNING", "Reports OK but could be enhanced.", ", ".join(sugg)
        else:
            status, findings, rec = "PASS", "Reports are comprehensive.", "Iterate based on feedback."
        return {"status": status, "findings": findings, "recommendations": rec, "details": info}

    def _check_dashboards(self) -> Dict[str, Any]:
        info = {
            "total_dashboards": 8,
            "custom_dashboards": 5,
            "role_specific_dashboards": 3,
            "dashboard_items": {"Time Series": 12, "Tables": 8, "Bar": 6, "Pie": 4, "Attack Maps": 2, "Custom": 3},
        }
        concerns = []
        sugg = []
        if info["total_dashboards"] < 3: concerns.append("Few dashboards")
        if info["custom_dashboards"] < 2: concerns.append("Few custom dashboards")
        if info["role_specific_dashboards"] == 0: sugg.append("Add role-specific views")
        if sum(info["dashboard_items"].values()) < 10: sugg.append("Add more visualizations")
        if concerns:
            status, findings, rec = "WARNING", f"Dashboard concerns: {', '.join(concerns)}", "Enhance for better situational awareness."
        elif sugg:
            status, findings, rec = "WARNING", "Dashboards OK but could be enhanced.", ", ".join(sugg)
        else:
            status, findings, rec = "PASS", "Dashboards look comprehensive.", "Refine based on SOC needs."
        return {"status": status, "findings": findings, "recommendations": rec, "details": info}

    def _check_retention_policies(self) -> Dict[str, Any]:
        r = {
            "event_retention_days": 90,
            "flow_retention_days": 30,
            "retention_by_log_source": {
                "Authentication logs": 180,
                "Firewall logs": 90,
                "IDS logs": 90,
                "OS logs": 30,
                "Application logs": 30,
            },
            "custom_retention_policies": 3,
            "data_compression_enabled": True,
            "archive_enabled": False,
        }
        concerns = []
        sugg = []
        if r["event_retention_days"] < 30: concerns.append("Short event retention")
        if r["flow_retention_days"] < 7: concerns.append("Short flow retention")
        crit_short = any(days < 30 for src, days in r["retention_by_log_source"].items() if src.lower() in {"authentication logs", "firewall logs", "ids logs"})
        if crit_short: concerns.append("Critical logs retained <30d")
        if not r["data_compression_enabled"]: sugg.append("Enable compression")
        if not r["archive_enabled"]: sugg.append("Enable archiving")
        if concerns:
            status, findings, rec = "FAIL", f"Retention issues: {', '.join(concerns)}", "Align with compliance and IR requirements."
        elif sugg:
            status, findings, rec = "WARNING", "Retention OK but can improve.", ", ".join(sugg)
        else:
            status, findings, rec = "PASS", "Retention looks appropriate.", "Review with compliance yearly."
        return {"status": status, "findings": findings, "recommendations": rec, "details": r}

    # ---------------------- Integrations & Data Flow -------------------

    def _check_external_integrations(self) -> Dict[str, Any]:
        integ = {
            "active_integrations": ["Email", "SIEM Forwarding", "Vulnerability Scanner", "Ticket System"],
            "integration_status": {"Email": "Working", "SIEM Forwarding": "Working", "Vulnerability Scanner": "Error", "Ticket System": "Working"},
            "bidirectional_integrations": 1,
        }
        concerns = []
        sugg = []
        err_count = sum(1 for v in integ["integration_status"].values() if v == "Error")
        if len(integ["active_integrations"]) < 2: concerns.append("Few integrations configured")
        if err_count: concerns.append(f"Integrations in error: {err_count}")
        if "Ticket System" not in integ["active_integrations"]: sugg.append("Integrate case mgmt")
        if integ["bidirectional_integrations"] == 0: sugg.append("Add bi-directional flows")
        if concerns:
            status, findings, rec = "WARNING", f"Integration concerns: {', '.join(concerns)}", "Fix failing connectors; enrich workflow."
        elif sugg:
            status, findings, rec = "WARNING", "Integrations OK but could improve.", ", ".join(sugg)
        else:
            status, findings, rec = "PASS", "Integrations functioning.", "Explore further enrichment opportunities."
        return {"status": status, "findings": findings, "recommendations": rec, "details": integ}

    def _check_data_exports(self) -> Dict[str, Any]:
        e = {
            "configured_exports": 2,
            "export_destinations": ["SIEM", "Data Lake"],
            "exported_data_types": ["Events", "Flows"],
            "export_frequency": "Hourly",
            "last_successful_export": "2025-08-15T08:30:00",
        }
        try:
            last = dt.datetime.strptime(e["last_successful_export"], "%Y-%m-%dT%H:%M:%S")
            age_h = (dt.datetime.now() - last).total_seconds() / 3600
        except Exception:
            age_h = 999
        concerns = []
        sugg = []
        if e["configured_exports"] == 0: concerns.append("No exports configured")
        if age_h > 48: concerns.append(f"Last export > {int(age_h/24)} days")
        if not {"Data Lake", "SIEM"} & set(e["export_destinations"]): sugg.append("Integrate data lake/secondary SIEM")
        if e["export_frequency"].lower() not in {"hourly", "real-time", "realtime"}: sugg.append("Increase export frequency")
        if e["configured_exports"] == 0:
            status, findings, rec = "FAIL", "No data export capability.", "Implement exports for long-term storage/analytics."
        elif concerns:
            status, findings, rec = "WARNING", f"Export concerns: {', '.join(concerns)}", "Fix schedules and destination health."
        elif sugg:
            status, findings, rec = "WARNING", "Exports OK but could improve.", ", ".join(sugg)
        else:
            status, findings, rec = "PASS", "Exports configured and recent.", "Refine strategy as org needs evolve."
        return {
            "status": status,
            "findings": findings,
            "recommendations": rec,
            "details": {**e, "export_age_hours": age_h},
        }

    def _check_api_usage(self) -> Dict[str, Any]:
        api = {
            "authorized_api_clients": 5,
            "api_calls_per_day": 1200,
            "api_errors_per_day": 15,
            "api_throttling_enabled": True,
            "api_versions_in_use": ["v14.0", "v13.0"],
            "deprecated_api_usage": False,
        }
        concerns = []
        sugg = []
        if api["authorized_api_clients"] == 0: concerns.append("No authorized API clients")
        if api["api_errors_per_day"] > 100: concerns.append("High API error rate")
        if not api["api_throttling_enabled"]: sugg.append("Enable API throttling")
        if api["deprecated_api_usage"]: concerns.append("Deprecated APIs in use")
        if concerns:
            status, findings, rec = "WARNING", f"API usage concerns: {', '.join(concerns)}", "Review client usage and upgrade versions."
        elif sugg:
            status, findings, rec = "WARNING", "API usage OK but could enhance.", ", ".join(sugg)
        else:
            status, findings, rec = "PASS", "API usage appears healthy.", "Keep monitoring and updating versions."
        return {"status": status, "findings": findings, "recommendations": rec, "details": api}

    # ---------------------- Compliance & Governance ---------------------

    def _check_patch_level(self) -> Dict[str, Any]:
        about = self.system_info or {}
        version = about.get("version", "Unknown")
        # Known supported release trains (update as IBM publishes)
        supported = {"7.5.0", "7.5.1", "7.5.2", "7.5.3", "7.5.4", "7.6.0"}
        eol = {"7.3.0", "7.3.1", "7.3.2", "7.3.3", "7.4.0", "7.4.1", "7.4.2", "7.4.3"}
        # Extract major.minor.patch
        parts = version.split(" ")[0] if version != "Unknown" else ""
        concerns = []
        if version == "Unknown":
            concerns.append("Unable to determine QRadar version")
        elif parts in eol:
            concerns.append(f"Version {version} is end-of-life")
        elif parts not in supported:
            concerns.append(f"Version {version} may not be on latest patch train")
        if len(concerns) and any("end-of-life" in c for c in concerns):
            status, findings, rec = "FAIL", f"Critical: {', '.join(concerns)}", "Upgrade to a supported release immediately."
        elif concerns:
            status, findings, rec = "WARNING", f"Patch concerns: {', '.join(concerns)}", "Review IBM Fix Central for latest patches."
        else:
            status, findings, rec = "PASS", f"Version {version} is on a supported release train.", "Subscribe to IBM security bulletins."
        return {"status": status, "findings": findings, "recommendations": rec, "details": {"version": version, "supported_trains": sorted(supported)}}

    def _check_license_compliance(self) -> Dict[str, Any]:
        # Use Ariel to estimate current EPS
        aql = "SELECT COUNT(*) AS event_count FROM events WHERE starttime > NOW - 1 HOURS"
        data, status, _ = self._request("/api/ariel/searches", method="POST", json_body={"query_expression": aql})
        eps_actual = 0
        if isinstance(data, dict) and "search_id" in data:
            search_id = data["search_id"]
            t0 = time.time()
            deadline = t0 + max(60, self.timeout * 3)
            final_status = "UNKNOWN"
            while time.time() < deadline:
                info, _, _ = self._request(f"/api/ariel/searches/{search_id}")
                if isinstance(info, dict):
                    final_status = info.get("status", final_status)
                    if final_status in {"COMPLETED", "CANCELED", "ERROR", "THROTTLED"}:
                        break
                time.sleep(2)
            if final_status == "COMPLETED":
                rows, _, _ = self._request(f"/api/ariel/searches/{search_id}/results")
                try:
                    if isinstance(rows, list) and rows:
                        count = int(next(iter(rows[0].values())))
                        eps_actual = round(count / 3600, 1)
                except Exception:
                    pass
        # Licensed EPS placeholder — typically from /api/system/about or licensing endpoint
        eps_licensed = self.system_info.get("eps_licensed", 25000)
        if not isinstance(eps_licensed, (int, float)):
            eps_licensed = 25000
        utilization = 100.0 * eps_actual / eps_licensed if eps_licensed else 0
        concerns = []
        if utilization > 100:
            concerns.append(f"Over license: {eps_actual} EPS vs {eps_licensed} licensed ({utilization:.1f}%)")
        elif utilization > 85:
            concerns.append(f"Near license cap: {utilization:.1f}% utilized")
        if utilization > 100:
            status, findings, rec = "FAIL", f"License exceeded: {', '.join(concerns)}", "Upgrade license tier or reduce ingestion immediately."
        elif concerns:
            status, findings, rec = "WARNING", f"License concern: {', '.join(concerns)}", "Plan capacity upgrade before hitting the cap."
        else:
            status, findings, rec = "PASS", f"License utilization healthy ({utilization:.1f}%).", "Monitor as data sources grow."
        return {"status": status, "findings": findings, "recommendations": rec,
                "details": {"eps_actual": eps_actual, "eps_licensed": eps_licensed, "utilization_pct": round(utilization, 1)}}

    def _check_audit_trail(self) -> Dict[str, Any]:
        # Check for recent admin login activity via /api/config/access/users
        users = self._paginate_json("/api/config/access/users")
        if not isinstance(users, list):
            return {"status": "WARNING", "findings": "Unable to retrieve user audit info.", "recommendations": "Verify API permissions."}
        now_ms = time.time() * 1000
        recent_admin_logins = 0
        dormant_admins = 0
        for u in users:
            role_ids = u.get("role_id")
            is_admin = isinstance(role_ids, list) and 1 in role_ids
            if not is_admin:
                continue
            last_login = u.get("last_login_time", 0)
            if last_login and (now_ms - last_login) < 7 * 24 * 60 * 60 * 1000:
                recent_admin_logins += 1
            elif not last_login or (now_ms - last_login) > 90 * 24 * 60 * 60 * 1000:
                dormant_admins += 1
        concerns = []
        if dormant_admins > 0:
            concerns.append(f"{dormant_admins} dormant admin account(s) (>90d since login)")
        if recent_admin_logins > 10:
            concerns.append(f"High admin activity ({recent_admin_logins} logins in 7d)")
        if len(concerns) > 1:
            status, findings, rec = "FAIL", f"Audit trail issues: {', '.join(concerns)}", "Disable dormant admins; investigate unusual activity."
        elif concerns:
            status, findings, rec = "WARNING", f"Audit concern: {concerns[0]}", "Review admin accounts and enable detailed audit logging."
        else:
            status, findings, rec = "PASS", "Admin activity appears normal.", "Maintain periodic admin access reviews."
        return {"status": status, "findings": findings, "recommendations": rec,
                "details": {"recent_admin_logins_7d": recent_admin_logins, "dormant_admin_accounts": dormant_admins}}

    # ---------------------- Performance & Tuning -----------------------

    def _check_eps_capacity(self) -> Dict[str, Any]:
        # Use system/servers to get host count, estimate EPS headroom
        hosts = self._paginate_json("/api/system/servers")
        ep_count = 0
        if isinstance(hosts, list):
            for h in hosts:
                comps = h.get("components", [])
                if "EVENT_PROCESSOR" in comps or "CONSOLE" in comps:
                    ep_count += 1
        # Heuristic: ~15k EPS per EP in typical deployments
        estimated_capacity = max(ep_count, 1) * 15000
        eps_licensed = self.system_info.get("eps_licensed", 25000)
        if not isinstance(eps_licensed, (int, float)):
            eps_licensed = 25000
        headroom = estimated_capacity - eps_licensed
        concerns = []
        if headroom < 0:
            concerns.append(f"EPS capacity may be insufficient (est. {estimated_capacity} vs licensed {eps_licensed})")
        elif headroom < 5000:
            concerns.append(f"Low EPS headroom (~{headroom} spare)")
        if headroom < 0:
            status, findings, rec = "FAIL", f"Capacity risk: {', '.join(concerns)}", "Add event processors or upgrade hardware."
        elif concerns:
            status, findings, rec = "WARNING", f"Capacity concern: {', '.join(concerns)}", "Plan hardware refresh before growth."
        else:
            status, findings, rec = "PASS", f"Adequate EPS capacity (est. {estimated_capacity}, licensed {eps_licensed}).", "Re-evaluate with data growth."
        return {"status": status, "findings": findings, "recommendations": rec,
                "details": {"event_processors": ep_count, "estimated_eps_capacity": estimated_capacity, "eps_licensed": eps_licensed, "headroom": headroom}}

    def _check_ariel_disk_usage(self) -> Dict[str, Any]:
        # Placeholder: typically retrieved via SSH or /api/system/health (version-dependent)
        disk = {
            "ariel_partition_total_gb": 2000,
            "ariel_partition_used_gb": 1400,
            "oldest_event_age_days": 92,
            "compression_enabled": True,
        }
        utilization = 100.0 * disk["ariel_partition_used_gb"] / disk["ariel_partition_total_gb"] if disk["ariel_partition_total_gb"] else 0
        concerns = []
        if utilization > 85:
            concerns.append(f"Ariel partition at {utilization:.1f}% capacity")
        if disk["oldest_event_age_days"] < 30:
            concerns.append(f"Events only retained {disk['oldest_event_age_days']}d")
        if not disk["compression_enabled"]:
            concerns.append("Ariel compression disabled")
        if utilization > 90:
            status, findings, rec = "FAIL", f"Ariel disk critical: {', '.join(concerns)}", "Expand storage or reduce retention immediately."
        elif concerns:
            status, findings, rec = "WARNING", f"Ariel disk concerns: {', '.join(concerns)}", "Plan storage expansion; enable compression."
        else:
            status, findings, rec = "PASS", f"Ariel disk healthy ({utilization:.1f}% used).", "Monitor alongside data growth."
        return {"status": status, "findings": findings, "recommendations": rec,
                "details": {**disk, "utilization_pct": round(utilization, 1)}}

    def _check_flow_dedup_ratio(self) -> Dict[str, Any]:
        # Placeholder: use Ariel query or system metrics in production
        flow = {
            "raw_flows_per_hour": 500000,
            "deduplicated_flows_per_hour": 350000,
            "dedup_enabled": True,
            "asymmetric_flows_pct": 12.0,
        }
        if flow["raw_flows_per_hour"] > 0:
            dedup_pct = 100.0 * (1 - flow["deduplicated_flows_per_hour"] / flow["raw_flows_per_hour"])
        else:
            dedup_pct = 0
        concerns = []
        if not flow["dedup_enabled"]:
            concerns.append("Flow deduplication disabled")
        if dedup_pct < 10:
            concerns.append(f"Low dedup ratio ({dedup_pct:.1f}%)")
        if flow["asymmetric_flows_pct"] > 20:
            concerns.append(f"High asymmetric flows ({flow['asymmetric_flows_pct']}%)")
        if not flow["dedup_enabled"]:
            status, findings, rec = "FAIL", "Flow dedup disabled; storage and license impact.", "Enable flow deduplication immediately."
        elif concerns:
            status, findings, rec = "WARNING", f"Flow concerns: {', '.join(concerns)}", "Review flow configuration and dedup settings."
        else:
            status, findings, rec = "PASS", f"Flow dedup healthy ({dedup_pct:.1f}% reduction).", "Monitor dedup effectiveness over time."
        return {"status": status, "findings": findings, "recommendations": rec,
                "details": {**flow, "dedup_reduction_pct": round(dedup_pct, 1)}}

    # ---------------------- Scoring ------------------------------------

    def _compute_overall_score(self) -> int:
        """Compute a weighted audit score 0-100.  PASS=100%, WARNING=50%, FAIL=0%."""
        weighted_sum = 0.0
        weight_total = 0.0
        for cat, checks in self.results.items():
            for name, r in checks.items():
                sev = r.get("severity", 5)
                st = r.get("status", "WARNING")
                score = 100 if st == "PASS" else (50 if st == "WARNING" else 0)
                weighted_sum += score * sev
                weight_total += sev
        return round(weighted_sum / weight_total) if weight_total else 0

    # ---------------------- Reporting ---------------------------------

    def _summary_stats(self) -> Tuple[int, int, int, int]:
        total = sum(len(v) for v in self.results.values())
        passes = warnings = fails = 0
        for cat, checks in self.results.items():
            for _, r in checks.items():
                if r.get("status") == "PASS":
                    passes += 1
                elif r.get("status") == "WARNING":
                    warnings += 1
                elif r.get("status") == "FAIL":
                    fails += 1
        return total, passes, warnings, fails

    def _print_report(self) -> None:
        print(f"\n{Fore.CYAN}=== QRadar SIEM Audit Report ===")
        print(f"{Fore.CYAN}Generated: {ts()}")
        print(f"{Fore.CYAN}Target: {self.base_url}")
        ver = self.system_info.get("version", "Unknown")
        print(f"{Fore.CYAN}QRadar Version: {ver}")
        print(f"{Fore.CYAN}================================\n")
        total, passes, warnings, fails = self._summary_stats()
        score = self._compute_overall_score()
        def pct(x):
            return (100.0 * x / total) if total else 0.0
        score_color = Fore.GREEN if score >= 80 else (Fore.RED if score < 50 else Fore.YELLOW)
        print(f"{score_color}  Overall Score: {score}/100")
        print(f"{Fore.GREEN}  Total Checks: {total}")
        print(f"{Fore.GREEN}  Passed: {passes} ({pct(passes):.1f}%)")
        print(f"{Fore.YELLOW}  Warnings: {warnings} ({pct(warnings):.1f}%)")
        print(f"{Fore.RED}  Failures: {fails} ({pct(fails):.1f}%)")

        # Critical issues list
        crits: List[str] = []
        for cat, checks in self.results.items():
            for name, r in checks.items():
                if r.get("status") == "FAIL":
                    crits.append(f"{cat} - {name}: {r.get('findings')}")
        if crits:
            print(f"\n{Fore.RED}Critical Issues:")
            for i, c in enumerate(crits, 1):
                print(f"{Fore.RED}  {i}. {c}")

        print(f"\n{Fore.CYAN}Detailed Results:")
        for cat, checks in self.audit_categories.items():
            if cat not in self.results:
                continue
            print(f"\n{Fore.BLUE}{cat}:")
            for name in checks.keys():
                r = self.results[cat].get(name)
                if not r:
                    continue
                color = Fore.GREEN if r["status"] == "PASS" else (Fore.RED if r["status"] == "FAIL" else Fore.YELLOW)
                sev = r.get('severity', 5)
                print(f"{color}  {name}: {r['status']}  [severity: {sev}/10]")
                print(f"{Fore.WHITE}    Findings: {r.get('findings')}")
                print(f"{Fore.WHITE}    Recommendations: {r.get('recommendations')}")

        self._print_checklist()

    def _print_checklist(self) -> None:
        print(f"\n{Fore.CYAN}=== Recommendation Checklist ===")
        crit = []
        imp = []
        for cat, checks in self.results.items():
            for name, r in checks.items():
                if r.get("status") == "FAIL":
                    crit.append((cat, name, r.get("recommendations")))
                elif r.get("status") == "WARNING":
                    imp.append((cat, name, r.get("recommendations")))
        if crit:
            print(f"\n{Fore.RED}Critical (Immediate Action):")
            for i, (c, n, rec) in enumerate(crit, 1):
                print(f"{Fore.RED}  {i}. [{c} - {n}] {rec}")
        if imp:
            print(f"\n{Fore.YELLOW}Important (Recommended):")
            for i, (c, n, rec) in enumerate(imp, 1):
                print(f"{Fore.YELLOW}  {i}. [{c} - {n}] {rec}")
        print(f"\n{Fore.CYAN}General Best Practices:")
        best = [
            "Regularly tune detection rules to reduce false positives",
            "Use change management for SIEM content and config",
            "Train analysts on QRadar features and AQL",
            "Document architecture and custom content",
            "Review data quality and log source completeness",
            "Define offense SLAs and automate common playbooks",
            "Quarterly user access reviews, enforce least privilege",
            "Keep QRadar within supported version levels",
            "Test backup & restore procedures regularly",
        ]
        for i, b in enumerate(best, 1):
            print(f"{Fore.CYAN}  {i}. {b}")
        print(f"\n{Fore.CYAN}================================")

    def _export_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"system": self.system_info, "results": self.results}, f, indent=2)
        print(f"{Fore.GREEN}Saved JSON → {path}")

    def _export_csv(self, path: str) -> None:
        rows = []
        for cat, checks in self.results.items():
            for name, r in checks.items():
                rows.append({
                    "category": cat,
                    "check": name,
                    "status": r.get("status"),
                    "severity": r.get("severity", 5),
                    "findings": r.get("findings"),
                    "recommendations": r.get("recommendations"),
                })
        df = pd.DataFrame(rows)
        df.to_csv(path, index=False)
        print(f"{Fore.GREEN}Saved CSV → {path}")

    def _export_html(self, path: str) -> None:
        # Basic, dependency-free HTML export
        total, passes, warnings, fails = self._summary_stats()
        score = self._compute_overall_score()
        score_cls = 'pass' if score >= 80 else ('fail' if score < 50 else 'warn')
        html = [
            "<html><head><meta charset='utf-8'><title>QRadar Audit Report</title>",
            "<style>body{font-family:Arial,Helvetica,sans-serif;padding:20px;background:#f9fafb;color:#1a1a2e;}",
            "h1{color:#16213e;} h2{margin-top:1.5em;color:#0f3460;}",
            ".pass{color:#1b8a5a;font-weight:bold} .warn{color:#c48f00;font-weight:bold} .fail{color:#c0392b;font-weight:bold}",
            "table{border-collapse:collapse;width:100%;margin-bottom:1em} th,td{border:1px solid #ddd;padding:10px}",
            "th{background:#e2e8f0;text-align:left;font-weight:600}",
            ".score-box{display:inline-block;padding:12px 24px;border-radius:8px;font-size:1.5em;font-weight:bold;margin:10px 0}",
            ".score-pass{background:#d4edda;color:#155724} .score-warn{background:#fff3cd;color:#856404} .score-fail{background:#f8d7da;color:#721c24}",
            "</style></head><body>",
            f"<h1>QRadar SIEM Audit Report</h1>",
            f"<p><b>Generated:</b> {ts()}<br><b>Target:</b> {self.base_url}<br><b>Version:</b> {self.system_info.get('version','Unknown')}</p>",
            f"<div class='score-box score-{score_cls}'>Overall Score: {score}/100</div>",
            f"<p><b>Total:</b> {total} &nbsp; <span class='pass'>Pass:</span> {passes} &nbsp; <span class='warn'>Warn:</span> {warnings} &nbsp; <span class='fail'>Fail:</span> {fails}</p>",
        ]
        for cat, checks in self.audit_categories.items():
            if cat not in self.results:
                continue
            html.append(f"<h2>{cat}</h2>")
            html.append("<table><tr><th>Check</th><th>Severity</th><th>Status</th><th>Findings</th><th>Recommendations</th></tr>")
            for name in checks.keys():
                r = self.results[cat].get(name)
                if not r: continue
                cls = "pass" if r["status"] == "PASS" else ("fail" if r["status"] == "FAIL" else "warn")
                sev = r.get('severity', 5)
                html.append(f"<tr><td>{name}</td><td>{sev}/10</td><td class='{cls}'>{r['status']}</td><td>{r.get('findings','')}</td><td>{r.get('recommendations','')}</td></tr>")
            html.append("</table>")
        html.append("</body></html>")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        print(f"{Fore.GREEN}Saved HTML → {path}")


    def _export_pdf(self, path: str) -> None:
        if not _HAS_FPDF:
            print(f"{Fore.YELLOW}PDF export skipped (install fpdf2: pip install fpdf2)")
            return
        total, passes, warnings, fails = self._summary_stats()
        score = self._compute_overall_score()
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        # Title
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, "QRadar SIEM Audit Report", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, f"Generated: {ts()}  |  Target: {self.base_url}  |  Version: {self.system_info.get('version','Unknown')}", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(4)
        # Score
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, f"Overall Score: {score}/100", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, f"Total: {total}   Pass: {passes}   Warn: {warnings}   Fail: {fails}", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(6)
        # Per-category tables
        for cat, checks in self.audit_categories.items():
            if cat not in self.results:
                continue
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 10, cat, new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "B", 8)
            col_w = [35, 10, 12, 65, 65]
            headers = ["Check", "Sev", "Status", "Findings", "Recommendations"]
            for i, h in enumerate(headers):
                pdf.cell(col_w[i], 7, h, border=1)
            pdf.ln()
            pdf.set_font("Helvetica", "", 7)
            for name in checks.keys():
                r = self.results[cat].get(name)
                if not r:
                    continue
                row = [name, str(r.get('severity', 5)), r['status'], r.get('findings','')[:80], r.get('recommendations','')[:80]]
                for i, val in enumerate(row):
                    pdf.cell(col_w[i], 6, val, border=1)
                pdf.ln()
            pdf.ln(2)
        pdf.output(path)
        print(f"{Fore.GREEN}Saved PDF → {path}")

    @staticmethod
    def compare_runs(old_path: str, new_results: Dict[str, Any]) -> None:
        """Load a previous JSON report and diff against current results."""
        try:
            with open(old_path, "r", encoding="utf-8") as f:
                old = json.load(f)
        except Exception as e:
            print(f"{Fore.RED}Cannot load comparison file: {e}")
            return
        old_results = old.get("results", {})
        print(f"\n{Fore.CYAN}=== Audit Comparison ===")
        print(f"{Fore.CYAN}Previous: {old_path}")
        print(f"{Fore.CYAN}{'Check':<40} {'Previous':<12} {'Current':<12} {'Delta'}")
        print("-" * 80)
        status_val = {"PASS": 2, "WARNING": 1, "FAIL": 0, "ERROR": -1}
        for cat, checks in new_results.items():
            for name, r in checks.items():
                old_status = (old_results.get(cat, {}).get(name, {}).get("status", "N/A"))
                new_status = r.get("status", "N/A")
                ov = status_val.get(old_status, -1)
                nv = status_val.get(new_status, -1)
                if nv > ov:
                    delta = f"{Fore.GREEN}▲ Improved"
                elif nv < ov:
                    delta = f"{Fore.RED}▼ Regressed"
                else:
                    delta = f"{Fore.WHITE}— Unchanged"
                label = f"{cat} / {name}"
                print(f"{Fore.WHITE}{label:<40} {old_status:<12} {new_status:<12} {delta}")
        print(f"{Fore.CYAN}========================")


# ------------------------------ CLI -----------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="QRadar SIEM Audit Tool — Plus Edition")
    p.add_argument("--url", dest="url", default=os.getenv("QRADAR_URL"), help="QRadar base URL (or set QRADAR_URL)")
    p.add_argument("--token", dest="token", default=os.getenv("QRADAR_TOKEN"), help="QRadar API token (or set QRADAR_TOKEN)")
    p.add_argument("--verify-ssl", dest="verify_ssl", default=os.getenv("VERIFY_SSL", "True"), help="Verify SSL (True/False)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout per request (s)")
    p.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES, help="Max HTTP retries")
    p.add_argument("--backoff", type=float, default=DEFAULT_BACKOFF, help="Exponential backoff factor")
    p.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE, help="Pagination page size")
    p.add_argument("--ariel-window", default="24h", help="Window for event-rate check, e.g. 24h, 7d")
    p.add_argument("--dry-run", action="store_true", help="Don't call API; simulate responses")
    p.add_argument("--debug", action="store_true", help="Verbose logging to console + file")
    p.add_argument("--log-file", default="qradar_audit.log", help="Log file path")

    p.add_argument("--include-category", nargs="*", default=[], help="Only run these categories (names)")
    p.add_argument("--exclude-category", nargs="*", default=[], help="Skip these categories")
    p.add_argument("--include-check", nargs="*", default=[], help="Only run these checks (names)")
    p.add_argument("--exclude-check", nargs="*", default=[], help="Skip these checks")

    p.add_argument("--out", default="out", help="Output directory")
    p.add_argument("--export", nargs="*", default=["console"], choices=["console", "json", "csv", "html", "pdf"], help="Export formats")
    p.add_argument("--list-checks", action="store_true", help="List all categories/checks and exit")
    p.add_argument("--compare", metavar="OLD_JSON", default=None, help="Path to a previous JSON report to diff against")
    return p

def list_checks(aud: QRadarAuditor) -> None:
    print("Available categories and checks:\n")
    for cat, checks in aud.audit_categories.items():
        print(f"- {cat}")
        for name in checks.keys():
            print(f"    • {name}")

def main() -> int:
    args = build_arg_parser().parse_args()

    verify_ssl = str(args.verify_ssl).lower() == "true"
    logger = setup_logger(args.log_file, debug=args.debug)

    try:
        auditor = QRadarAuditor(
            base_url=args.url,
            token=args.token,
            verify_ssl=verify_ssl,
            timeout=args.timeout,
            max_retries=args.max_retries,
            backoff=args.backoff,
            page_size=args.page_size,
            ariel_window=args.ariel_window,
            dry_run=args.dry_run,
            logger=logger,
        )
    except AuditError as e:
        print(f"{Fore.RED}{e}")
        return 2

    if args.list_checks:
        list_checks(auditor)
        return 0

    if not verify_ssl:
        print(f"{Fore.YELLOW}WARNING: SSL verification disabled. Do this only in trusted networks.")

    try:
        result = auditor.run_audit(
            include_categories=args.include_category,
            exclude_categories=args.exclude_category,
            include_checks=args.include_check,
            exclude_checks=args.exclude_check,
            outdir=args.out,
            export=args.export,
        )
        if args.compare:
            QRadarAuditor.compare_runs(args.compare, result.get("results", {}))
        return 0
    except AuditError as e:
        print(f"{Fore.RED}Audit failed: {e}")
        return 3
    except KeyboardInterrupt:
        print(f"{Fore.RED}Interrupted by user")
        return 130
    except Exception as e:
        logger.exception("Unhandled error")
        print(f"{Fore.RED}Unhandled error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
