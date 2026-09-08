#!/usr/bin/env python3
"""
check_macro_policy.py

Checks CrowdStrike Falcon prevention policies for the "Microsoft Office File
Suspicious Macro Removal" setting.  Supports CrowdStrike Flight Control (MSSP)
for multi-CID environments and can optionally disable the setting via the API.
"""

import argparse
import csv
import json
import os
import sys
import time
from typing import Optional

import requests

# Load .env if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_BASE_URL = "https://api.crowdstrike.com"
TOKEN_PATH = "/oauth2/token"
POLICY_COMBINED_PATH = "/policy/combined/prevention/v1"
POLICY_ENTITIES_PATH = "/policy/entities/prevention/v1"
MSSP_QUERY_PATH = "/mssp/queries/children/v1"
MSSP_ENTITIES_PATH = "/mssp/entities/children/v2"

# Known API setting IDs for "Microsoft Office File Suspicious Macro Removal".
# Matched in priority order; name-substring fallback handles any spelling variation.
MACRO_SETTING_IDS = {
    "MicrosoftOfficeFileSuspiciousMacroRemoval",
    "OfficeMacroRemoval",
    "SuspiciousMacroRemoval",
    "MicrosoftOfficeSuspiciousMacroRemoval",
}

# ── Terminal colours ──────────────────────────────────────────────────────────

def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

if _use_color():
    _R  = "\033[0m"     # reset
    _B  = "\033[1m"     # bold
    _RE = "\033[1;31m"  # bold red   — errors / ENABLED (needs action)
    _GR = "\033[1;32m"  # bold green — success / DISABLED (OK)
    _YE = "\033[33m"    # yellow     — warnings / NOT FOUND
    _CY = "\033[36m"    # cyan       — headers / dividers
else:
    _R = _B = _RE = _GR = _YE = _CY = ""

# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Check (and optionally modify) the CrowdStrike Falcon macro removal prevention policy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables (or .env file):
  FALCON_CLIENT_ID      API client ID           (required)
  FALCON_CLIENT_SECRET  API client secret        (required)
  FALCON_BASE_URL       API base URL             (default: https://api.crowdstrike.com)

Examples:
  python check_macro_policy.py
  python check_macro_policy.py --output json
  python check_macro_policy.py --csv results.csv
  python check_macro_policy.py --no-interactive --csv results.csv
""",
    )
    p.add_argument(
        "--output", choices=["plain", "json"], default="plain",
        help="Terminal output format (default: plain)",
    )
    p.add_argument(
        "--csv", metavar="FILE",
        help="Export results to a CSV file",
    )
    p.add_argument(
        "--no-interactive", action="store_true",
        help="Skip all interactive prompts (for automation / CI)",
    )
    p.add_argument(
        "--debug", action="store_true",
        help="Print PATCH request/response details for troubleshooting",
    )
    return p.parse_args()

# ── Credentials ───────────────────────────────────────────────────────────────

def load_credentials() -> tuple:
    client_id = os.environ.get("FALCON_CLIENT_ID", "").strip()
    client_secret = os.environ.get("FALCON_CLIENT_SECRET", "").strip()
    base_url = os.environ.get("FALCON_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

    missing = [name for name, val in [
        ("FALCON_CLIENT_ID", client_id),
        ("FALCON_CLIENT_SECRET", client_secret),
    ] if not val]

    if missing:
        print(f"{_RE}ERROR:{_R} Missing required environment variable(s): {', '.join(missing)}")
        print("Set them in your shell or create a .env file next to this script.")
        sys.exit(1)

    return client_id, client_secret, base_url

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _extract_errors(body: dict) -> str:
    errors = body.get("errors") or []
    return "; ".join(e.get("message", str(e)) for e in errors) if errors else ""


def _request(method: str, url: str, max_retries: int = 3, **kwargs) -> requests.Response:
    for attempt in range(max_retries):
        try:
            resp = requests.request(method, url, timeout=30, **kwargs)
        except requests.exceptions.RequestException as exc:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            print(f"{_RE}ERROR:{_R} Network error: {exc}")
            sys.exit(1)

        if resp.status_code == 429:
            wait = 2 ** attempt
            print(f"  {_YE}Rate limited (429). Waiting {wait}s before retry {attempt + 1}/{max_retries}...{_R}")
            time.sleep(wait)
            continue

        return resp

    print(f"{_RE}ERROR:{_R} Request failed after maximum retries.")
    sys.exit(1)

# ── Authentication ─────────────────────────────────────────────────────────────

def get_token(
    base_url: str,
    client_id: str,
    client_secret: str,
    member_cid: Optional[str] = None,
) -> str:
    data: dict = {"client_id": client_id, "client_secret": client_secret}
    if member_cid:
        data["member_cid"] = member_cid

    resp = _request(
        "POST", f"{base_url}{TOKEN_PATH}",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    if resp.status_code == 201:
        return resp.json()["access_token"]

    try:
        body = resp.json()
        msg = _extract_errors(body) or resp.text
    except Exception:
        msg = resp.text

    if resp.status_code == 401:
        print(f"{_RE}ERROR:{_R} Authentication failed. Verify FALCON_CLIENT_ID and FALCON_CLIENT_SECRET.\nDetails: {msg}")
    elif resp.status_code == 403:
        print(f"{_RE}ERROR:{_R} Access denied. Ensure the API client has the required scopes.\nDetails: {msg}")
    else:
        print(f"{_RE}ERROR:{_R} Token request failed (HTTP {resp.status_code}): {msg}")

    sys.exit(1)

# ── Flight Control ─────────────────────────────────────────────────────────────

def get_child_cids(base_url: str, token: str) -> list:
    """Return list of {id, name} dicts for all Flight Control child CIDs.
    Returns [] if this is not an MSSP parent or the scope is absent."""
    headers = {"Authorization": f"Bearer {token}"}

    resp = _request("GET", f"{base_url}{MSSP_QUERY_PATH}", headers=headers, params={"limit": 5000})

    if resp.status_code in (400, 403, 404):
        return []
    if resp.status_code != 200:
        return []

    child_ids: list = resp.json().get("resources") or []
    if not child_ids:
        return []

    # Fetch entity details in batches of 20 (API ceiling per request)
    children: list = []
    for i in range(0, len(child_ids), 20):
        batch = child_ids[i : i + 20]
        resp2 = _request(
            "GET", f"{base_url}{MSSP_ENTITIES_PATH}",
            headers=headers,
            params=[("ids", cid) for cid in batch],
        )
        if resp2.status_code != 200:
            children.extend({"id": cid, "name": cid} for cid in batch)
            continue
        for r in resp2.json().get("resources") or []:
            children.append({
                "id": r.get("child_cid", r.get("id", "")),
                "name": r.get("name", r.get("child_cid", "")),
            })

    return children


def select_cids(child_cids: list) -> list:
    """Interactive CID selector. Returns list of CID strings; None = parent/direct."""
    print("\n" + _CY + "=" * 62 + _R)
    print(_B + "SELECT CIDs TO CHECK" + _R)
    print(_CY + "=" * 62 + _R)
    print(f"  [  0]  Parent / Direct CID")
    for i, cid in enumerate(child_cids, 1):
        print(f"  [{i:>3}]  {cid['name']:<42} {cid['id']}")

    print(
        "\nEnter CID numbers to check (comma-separated, e.g. '0,2,5'),\n"
        "'all' for every CID, or '0' for the parent only:"
    )
    choice = input("  Selection > ").strip().lower()

    if choice in ("all", "*"):
        return [None] + [c["id"] for c in child_cids]

    selected: list = []
    for part in choice.split(","):
        try:
            idx = int(part.strip())
            if idx == 0:
                selected.append(None)
            elif 1 <= idx <= len(child_cids):
                selected.append(child_cids[idx - 1]["id"])
        except ValueError:
            pass

    return selected if selected else [None]

# ── Policy fetch ──────────────────────────────────────────────────────────────

def fetch_windows_policies(base_url: str, token: str) -> Optional[list]:
    """Fetch all Windows prevention policies with automatic pagination.
    Returns None if access is denied (403) so the caller can skip gracefully."""
    headers = {"Authorization": f"Bearer {token}"}
    all_policies: list = []
    offset = 0
    limit = 100

    while True:
        resp = _request(
            "GET", f"{base_url}{POLICY_COMBINED_PATH}",
            headers=headers,
            params={
                "filter": 'platform_name:"Windows"',
                "limit": limit,
                "offset": offset,
            },
        )

        if resp.status_code >= 400:
            try:
                msg = _extract_errors(resp.json()) or resp.text
            except Exception:
                msg = resp.text
            if resp.status_code == 403:
                return None
            print(f"{_RE}ERROR:{_R} Failed to fetch policies (HTTP {resp.status_code}): {msg}")
            sys.exit(1)

        body = resp.json()
        errs = _extract_errors(body)
        if errs:
            print(f"{_RE}ERROR:{_R} API error in policy response: {errs}")
            sys.exit(1)

        resources: list = body.get("resources") or []
        all_policies.extend(resources)

        total: int = (body.get("meta") or {}).get("pagination", {}).get("total", 0)
        offset += len(resources)

        if offset >= total or not resources:
            break

    return all_policies

# ── Setting search ─────────────────────────────────────────────────────────────

def find_macro_setting(policy: dict) -> Optional[dict]:
    """Walk prevention_settings groups to find the macro removal toggle."""
    for group in policy.get("prevention_settings") or []:
        for setting in group.get("settings") or []:
            if setting.get("id") in MACRO_SETTING_IDS:
                return setting
            name_lower = setting.get("name", "").lower()
            if "macro" in name_lower and "removal" in name_lower:
                return setting
    return None

# ── Report ─────────────────────────────────────────────────────────────────────

def build_report(policies: list, cid_label: str = "") -> list:
    rows = []
    for policy in policies:
        setting = find_macro_setting(policy)
        rows.append({
            "cid": cid_label,
            "policy_id": policy.get("id", ""),
            "policy_name": policy.get("name", ""),
            "policy_enabled": policy.get("enabled"),
            "setting_id": setting.get("id", "") if setting else "",
            "setting_name": setting.get("name", "") if setting else "",
            "macro_removal_enabled": (
                setting.get("value", {}).get("enabled") if setting else None
            ),
        })
    return rows


def _count_states(report: list) -> tuple:
    """Return (enabled_count, disabled_count, not_found_count) for a report."""
    en  = sum(1 for r in report if r["macro_removal_enabled"] is True)
    dis = sum(1 for r in report if r["macro_removal_enabled"] is False)
    nf  = sum(1 for r in report if r["macro_removal_enabled"] is None)
    return en, dis, nf


def render_summary(report: list, header: str = "") -> str:
    """One-line-per-count summary — shown by default."""
    en, dis, nf = _count_states(report)
    lines = [
        "\n" + _CY + "=" * 62 + _R,
        _B + (header or "Current CID") + _R,
        _CY + "=" * 62 + _R,
    ]
    lines.append(f"  Total policies          : {_B}{len(report)}{_R}")
    en_str  = f"{_RE}{en}{_R}"  if en  else str(en)
    dis_str = f"{_GR}{dis}{_R}" if dis else str(dis)
    nf_str  = f"{_YE}{nf}{_R}"  if nf  else str(nf)
    lines.append(f"  Needs disabling         : {en_str}  (macro removal ENABLED)")
    lines.append(f"  OK (already disabled)   : {dis_str}")
    lines.append(f"  Setting not found       : {nf_str}  (policy predates this control — no action needed)")
    return "\n".join(lines)


def render_plain(report: list, header: str = "") -> str:
    """Full per-policy listing."""
    lines = [
        "\n" + _CY + "=" * 62 + _R,
        _B + (header or "Current CID") + _R,
        _CY + "=" * 62 + _R,
    ]
    lines.append(f"Windows prevention polic{'y' if len(report) == 1 else 'ies'} found: {len(report)}\n")

    for r in report:
        p_status = "ENABLED" if r["policy_enabled"] else "DISABLED"
        p_color  = _YE if r["policy_enabled"] else _GR
        lines.append(f'  Policy : {_B}"{r["policy_name"]}"{_R}')
        lines.append(f'  ID     : {r["policy_id"]}  |  Policy: {p_color}{p_status}{_R}')

        if r["macro_removal_enabled"] is True:
            lines.append(f'  Macro Removal ({r["setting_id"]}): {_RE}ENABLED  <-- NEEDS DISABLING{_R}')
        elif r["macro_removal_enabled"] is False:
            lines.append(f'  Macro Removal ({r["setting_id"]}): {_GR}DISABLED (OK){_R}')
        else:
            lines.append(f'  Macro Removal: {_YE}NOT FOUND{_R} (policy predates this control — no action needed)')
        lines.append("")

    en, dis, nf = _count_states(report)
    en_s  = f"{_RE}{en} ENABLED (needs disabling){_R}"   if en  else f"{en} ENABLED (needs disabling)"
    dis_s = f"{_GR}{dis} DISABLED (OK){_R}"              if dis else f"{dis} DISABLED (OK)"
    nf_s  = f"{_YE}{nf} NOT FOUND{_R}"                   if nf  else f"{nf} NOT FOUND"
    lines.append(f"  Summary: {en_s} | {dis_s} | {nf_s}")
    return "\n".join(lines)

# ── CSV export ─────────────────────────────────────────────────────────────────

def export_csv(results: list, path: str) -> None:
    fieldnames = [
        "cid", "policy_id", "policy_name", "policy_enabled",
        "setting_id", "setting_name", "macro_removal_enabled",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"\n{_GR}Results written to: {path}{_R}")

# ── Policy update ──────────────────────────────────────────────────────────────

def patch_policy_setting(
    base_url: str,
    token: str,
    policy_id: str,
    setting_id: str,
    enable: bool,
    debug: bool = False,
) -> tuple:
    """
    Read-modify-write a single prevention setting.
    Fetches the current setting value, applies the change, and PATCHes it back.
    Returns (success, error_msg|None).
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    fetch = _request(
        "GET", f"{base_url}{POLICY_ENTITIES_PATH}",
        headers=headers,
        params={"ids": policy_id},
    )
    if fetch.status_code != 200:
        return False, f"Pre-fetch failed (HTTP {fetch.status_code}): {fetch.text}"

    resources = (fetch.json().get("resources") or [])
    if not resources:
        return False, "Policy not returned when fetching for update"

    policy = resources[0]
    existing = find_macro_setting(policy)
    if not existing:
        return False, f"Setting '{setting_id}' not found inside policy"

    if debug:
        print(f"  [DEBUG] PRE-FETCH  setting id='{existing.get('id')}' value={existing.get('value')}")

    # Preserve all sub-fields in the value dict (e.g. "configured") — the API
    # requires the complete value object; sending only {"enabled": …} zeros out
    # any other fields present on the setting.
    setting_value = dict(existing.get("value") or {})
    setting_value["enabled"] = enable

    # The Falcon REST API PATCH endpoint uses the field name "settings" (flat array
    # of {id, value} pairs) to write setting changes.  "prevention_settings" is the
    # grouped read-only field returned by GET; sending it in a PATCH body returns
    # HTTP 200 but the API silently ignores it.
    payload = {
        "resources": [
            {
                "id": policy_id,
                "settings": [
                    {"id": existing.get("id"), "value": setting_value}
                ],
            }
        ]
    }

    if debug:
        print(f"\n  [DEBUG] PATCH payload:\n{json.dumps(payload, indent=2)}")

    resp = _request(
        "PATCH", f"{base_url}{POLICY_ENTITIES_PATH}",
        headers=headers,
        json=payload,
    )

    if debug:
        try:
            rbody = resp.json()
            patched_setting = None
            for r in rbody.get("resources") or []:
                patched_setting = find_macro_setting(r)
                if patched_setting:
                    break
            patched_val = patched_setting.get("value") if patched_setting else None
            errs_in_resp = _extract_errors(rbody)
            print(f"  [DEBUG] PATCH response HTTP {resp.status_code} | errors='{errs_in_resp}' | target setting after PATCH={patched_val}")
        except Exception as exc:
            print(f"  [DEBUG] PATCH response (HTTP {resp.status_code}): {resp.text[:500]} | parse error: {exc}")

    if resp.status_code == 200:
        try:
            errs = _extract_errors(resp.json())
            if errs:
                return False, f"API accepted request but reported errors: {errs}"
        except Exception:
            pass
        return True, None

    try:
        msg = _extract_errors(resp.json()) or resp.text
    except Exception:
        msg = resp.text

    return False, f"HTTP {resp.status_code}: {msg}"


def verify_policy_setting(base_url: str, token: str, policy_id: str, debug: bool = False) -> Optional[bool]:
    """Re-fetch a policy and return the current macro removal enabled state."""
    resp = _request(
        "GET", f"{base_url}{POLICY_ENTITIES_PATH}",
        headers={"Authorization": f"Bearer {token}"},
        params={"ids": policy_id},
    )
    if resp.status_code != 200:
        return None
    verified_val = None
    for r in (resp.json().get("resources") or []):
        setting = find_macro_setting(r)
        if setting:
            verified_val = setting.get("value", {}).get("enabled")
            if debug:
                print(f"  [DEBUG] VERIFY     setting id='{setting.get('id')}' value={setting.get('value')}")
            break
    return verified_val

# ── Interactive disable prompt ─────────────────────────────────────────────────

def prompt_disable(
    all_results: list,
    base_url: str,
    client_id: str,
    client_secret: str,
    debug: bool = False,
) -> None:
    """Prompt the user to disable macro removal on policies where it is ENABLED."""
    enabled_policies = [
        r for r in all_results
        if r.get("setting_id") and r["macro_removal_enabled"] is True
    ]

    if not enabled_policies:
        print(f"\n{_GR}No policies have macro removal ENABLED. Nothing to disable.{_R}")
        return

    print("\n" + _CY + "=" * 62 + _R)
    print(_B + "DISABLE MACRO REMOVAL" + _R)
    print(f"  {len(enabled_policies)} polic{'y' if len(enabled_policies) == 1 else 'ies'} currently have the setting {_RE}ENABLED{_R}:")
    print(_CY + "=" * 62 + _R)
    for i, r in enumerate(enabled_policies, 1):
        cid_info = f"  CID: {r['cid']}" if r["cid"] else ""
        print(f"  [{i:>3}]  \"{r['policy_name']}\" [{r['policy_id']}]{cid_info}")

    print(
        "\nEnter policy numbers to DISABLE (comma-separated, e.g. '1,3'),\n"
        "'all' to disable on all listed policies, or 'skip' to make no changes:"
    )
    choice = input("  Selection > ").strip().lower()

    if choice in ("skip", "s", ""):
        print("Skipped — no changes made.")
        return

    if choice in ("all", "*"):
        selected = enabled_policies
    else:
        selected = []
        for part in choice.split(","):
            try:
                idx = int(part.strip())
                if 1 <= idx <= len(enabled_policies):
                    selected.append(enabled_policies[idx - 1])
            except ValueError:
                pass

    if not selected:
        print("No valid selection. Skipped.")
        return

    print(
        f"\n{_YE}About to DISABLE macro removal on "
        f"{len(selected)} polic{'y' if len(selected) == 1 else 'ies'}.{_R}"
    )
    confirm = input("  Type 'yes' or 'y' to confirm, anything else to cancel: ").strip().lower()
    if confirm not in ("yes", "y"):
        print("Cancelled — no changes made.")
        return

    # Group by CID so we request one token per CID
    by_cid: dict = {}
    for r in selected:
        by_cid.setdefault(r.get("cid") or "", []).append(r)

    print()
    for cid_key, policies in by_cid.items():
        member_cid = cid_key if cid_key else None
        cid_token = get_token(base_url, client_id, client_secret, member_cid=member_cid)

        for r in policies:
            ok, err = patch_policy_setting(
                base_url, cid_token,
                r["policy_id"], r["setting_id"],
                enable=False,
                debug=debug,
            )
            label = f'"{r["policy_name"]}"' + (f' [CID: {cid_key}]' if cid_key else "")
            if ok:
                new_state = verify_policy_setting(base_url, cid_token, r["policy_id"], debug=debug)
                if new_state is False:
                    print(f"  {_GR}DISABLED (verified):{_R} {label}")
                elif new_state is True:
                    print(f"  {_YE}WARNING — API accepted the change but setting still reads ENABLED:{_R} {label}")
                    print(f"            This may be a brief propagation delay; re-run in a few seconds to confirm.")
                    print(f"            If it persists, verify the API client has Prevention Policies: Write scope.")
                else:
                    print(f"  {_YE}PATCHED (could not re-verify):{_R} {label}")
            else:
                print(f"  {_RE}FAILED:{_R} {label} — {err}")

# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()
    client_id, client_secret, base_url = load_credentials()

    print()
    print(_CY + _B + "CrowdStrike Falcon — Microsoft Office Macro Removal Policy Check" + _R)
    print(_CY + "=" * 62 + _R)

    print(f"\n{_B}[1/5]{_R} Authenticating...")
    token = get_token(base_url, client_id, client_secret)
    print(f"      {_GR}OK{_R}")

    print(f"\n{_B}[2/5]{_R} Checking for Flight Control child CIDs...")
    child_cids = get_child_cids(base_url, token)

    if child_cids:
        print(f"      Found {_B}{len(child_cids)}{_R} child CID(s).")
        if args.no_interactive:
            selected_cids = [None] + [c["id"] for c in child_cids]
            print(f"      Non-interactive: processing all {_B}{len(selected_cids)}{_R} CID(s).")
        else:
            selected_cids = select_cids(child_cids)
    else:
        print("      No Flight Control child CIDs found (or Flight Control scope not granted).")
        print("      Operating on the current CID only.")
        selected_cids = [None]

    print(f"\n{_B}[3/5]{_R} Enumerating Windows prevention policies across {_B}{len(selected_cids)}{_R} CID(s)...")

    all_results: list = []

    for member_cid in selected_cids:
        display_label = f"CID: {member_cid}" if member_cid else "Parent / Direct CID"

        if member_cid:
            cid_token = get_token(base_url, client_id, client_secret, member_cid=member_cid)
        else:
            cid_token = token

        print(f"  Fetching policies for {display_label}...", end=" ", flush=True)
        policies = fetch_windows_policies(base_url, cid_token)
        if policies is None:
            print(f"\n  {_YE}Skipped — access denied (403). Ensure the API client has the Prevention Policies: Read scope.{_R}")
            continue
        print(f"found {len(policies)} polic{'y' if len(policies) == 1 else 'ies'}.")

        if not policies:
            continue

        report = build_report(policies, cid_label=member_cid or "")
        all_results.extend(report)

        if args.output == "json":
            print(json.dumps(report, indent=2, default=str))
        else:
            print(render_summary(report, header=display_label))
            if not args.no_interactive:
                ans = input("\n  Show all policies? (yes/no) > ").strip().lower()
                if ans in ("yes", "y"):
                    print(render_plain(report, header=display_label))

    if not all_results:
        print(f"\n{_YE}No Windows prevention policies found across selected CIDs.{_R}")
        sys.exit(0)

    print(f"\n{_B}[4/5]{_R} Export results to CSV")

    if args.csv:
        export_csv(all_results, args.csv)
    elif not args.no_interactive:
        print("\nExport results to CSV? Enter a filename, or press Enter to skip:")
        csv_path = input("  Filename > ").strip()
        if csv_path:
            export_csv(all_results, csv_path)

    print(f"\n{_B}[5/5]{_R} Disable macro removal on flagged policies")

    if not args.no_interactive:
        prompt_disable(all_results, base_url, client_id, client_secret, debug=args.debug)
    else:
        en, dis, nf = _count_states(all_results)
        if en:
            print(
                f"\n  {_RE}{en} polic{'y' if en == 1 else 'ies'} ENABLED (macro removal active){_R} — "
                f"run interactively to disable."
            )
        if dis or nf:
            print(
                f"  {_GR}{dis} polic{'y' if dis == 1 else 'ies'} already disabled{_R}, "
                f"{_YE}{nf} NOT FOUND{_R} (no action needed)."
            )

    print(f"\n{_GR}Done.{_R}\n")


if __name__ == "__main__":
    main()
