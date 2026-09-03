# CrowdStrike Falcon — Microsoft Office Macro Removal Prevention Policy Check

A standalone Python script that checks whether the **Microsoft Office File
Suspicious Macro Removal** setting is enabled across Windows prevention policies
in one or more CrowdStrike Falcon CIDs. Supports CrowdStrike **Flight Control
(MSSP)** for multi-tenant environments and can interactively disable the setting
on selected policies via the API.

---

## What the Script Does

1. **Authenticates** to the CrowdStrike Falcon API using OAuth2 client credentials.
2. **Enumerates CIDs** — queries for Flight Control child CIDs and prompts you to
   select which CIDs to operate on (parent only, a subset, or all).
3. **Fetches Windows prevention policies** for each selected CID (pagination is
   handled automatically).
4. **Searches** each policy's settings for the macro removal toggle and reports its
   current enabled/disabled state in the terminal.
5. **Optionally exports** all results to a CSV file.
6. **Prompts you to disable** the setting on any policies where it is currently
   enabled, confirming before any change is made.

---

## Requirements

### Python version

Python **3.8** or newer.

### Python packages

| Package | Version | Purpose |
|---|---|---|
| `requests` | ≥ 2.28.0 | All HTTP calls to the Falcon API |
| `python-dotenv` | ≥ 1.0.0 | Auto-load credentials from a `.env` file |

### Creating a virtual environment (recommended)

A virtual environment keeps the script's dependencies isolated from your system
Python installation.

**macOS / Linux:**

```bash
# Create the virtual environment in a folder called .venv
python3 -m venv .venv

# Activate it
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**Windows (Command Prompt):**

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> **Tip:** Your prompt will show `(.venv)` when the environment is active.
> Run `deactivate` to leave it. You need to activate the environment again
> each time you open a new terminal session before running the script.

### CrowdStrike API Scopes

Create an API client in **Support & Resources → API Clients and Keys** with the
following scopes:

| Scope | Access | Required For |
|---|---|---|
| Prevention Policies | **Read** | Reading policy settings |
| Prevention Policies | **Write** | Disabling the setting (step 5) |
| Flight Control (MSSP) | **Read** | Enumerating child CIDs — multi-CID only |

> **Note:** Flight Control scope is optional. If absent, the script operates on
> the parent/direct CID only. Prevention Policies Write is only needed if you
> intend to disable the setting; the read/check steps work without it.

---

## Setup

### 1. Create a CrowdStrike API Client

1. Log in to the Falcon console.
2. Navigate to **Support & Resources → API Clients and Keys**.
3. Click **Create API Client**.
4. Grant the scopes listed above.
5. Copy the **Client ID** and **Client Secret** (the secret is only shown once).

### 2. Configure Credentials

```bash
cp .env.example .env
```

Edit `.env` and fill in your values:

```dotenv
FALCON_CLIENT_ID=abc123...
FALCON_CLIENT_SECRET=xyz789...
# FALCON_BASE_URL=https://api.crowdstrike.com
```

The script loads `.env` automatically if `python-dotenv` is installed.
Alternatively, export the variables in your shell before running:

```bash
export FALCON_CLIENT_ID=abc123...
export FALCON_CLIENT_SECRET=xyz789...
```

---

## Usage

### Interactive mode (default)

```bash
python check_macro_policy.py
```

The script walks you through each step interactively:

1. Authenticates and checks for Flight Control child CIDs.
2. Displays available CIDs and prompts for a selection.
3. Fetches and displays Windows prevention policies for each selected CID.
4. Asks whether to export results to a CSV file.
5. Lists policies with macro removal **ENABLED** and offers to disable them.

### Non-interactive mode (automation / CI)

```bash
python check_macro_policy.py --no-interactive
```

Skips all prompts, processes **all** CIDs (parent + any Flight Control children),
and reports results to the terminal. Combine with `--csv` to save output.

### Options

| Flag | Description |
|---|---|
| `--output plain\|json` | Terminal output format (default: `plain`) |
| `--csv FILE` | Write results to `FILE` without prompting |
| `--no-interactive` | Suppress all prompts (safe for scripting) |

### Examples

```bash
# Default interactive run
python check_macro_policy.py

# Export to CSV automatically (skips the CSV prompt)
python check_macro_policy.py --csv results.csv

# Output raw JSON for downstream tools (jq, etc.)
python check_macro_policy.py --output json

# Fully non-interactive with CSV export
python check_macro_policy.py --no-interactive --csv output.csv

# Non-interactive JSON output
python check_macro_policy.py --no-interactive --output json
```

---

## Sample Output

### Plain text

```
CrowdStrike Falcon — Microsoft Office Macro Removal Policy Check
==============================================================

[1/4] Authenticating...
      OK

[2/4] Checking for Flight Control child CIDs...
      Found 2 child CID(s).

STEP 1 — SELECT CIDs TO ENUMERATE
==============================================================
  [  0]  Parent / Direct CID
  [  1]  Acme Corp — Production          abc123456789abcd
  [  2]  Acme Corp — Dev/Test            def987654321efgh

Enter CID numbers to check (comma-separated), 'all', or '0':
  Selection > all

[3/4] Enumerating Windows prevention policies across 3 CID(s)...
  Fetching policies for Parent / Direct CID... found 1 policy.

==============================================================
Parent / Direct CID
==============================================================
Windows prevention policies found: 1

  Policy : "Corporate Windows Baseline"
  ID     : aaa111...  |  Policy: ENABLED
  Macro Removal (SuspiciousMacroRemoval): ENABLED

  Summary: 1 ENABLED | 0 DISABLED | 0 NOT FOUND

  Fetching policies for CID: abc123456789abcd... found 2 policies.
  ...

[4/4] Export & optional modifications
Export results to CSV? Enter a filename, or press Enter to skip:
  Filename > results.csv

Results written to: results.csv
```

### CSV columns

| Column | Description |
|---|---|
| `cid` | CID the policy belongs to (blank = parent/direct) |
| `policy_id` | Falcon prevention policy ID |
| `policy_name` | Policy display name |
| `policy_enabled` | Whether the policy itself is active (`True`/`False`) |
| `setting_id` | API setting ID found (e.g. `SuspiciousMacroRemoval`) |
| `setting_name` | Human-readable setting name from the API |
| `macro_removal_enabled` | `True`, `False`, or blank (setting not present in policy) |

---

## Multi-CID / Flight Control

If your API client belongs to an MSSP parent CID, the script automatically
discovers child CIDs via `GET /mssp/queries/children/v1`. In interactive mode
you can select any combination of CIDs. The script requests a scoped OAuth2
token for each child CID using the `member_cid` parameter, so credentials are
never stored per-child.

The Flight Control (MSSP) Read scope is **optional**. If it is absent or the
account is not an MSSP parent, the script silently falls back to operating on
the direct CID only.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `ERROR: Authentication failed` | Wrong `FALCON_CLIENT_ID` or `FALCON_CLIENT_SECRET` |
| `ERROR: Access denied (403)` | API client is missing a required scope |
| Setting shows as `NOT FOUND` | Policy template predates this control, or the setting ID differs; open an issue |
| `FAILED: HTTP 403` on PATCH | Client lacks **Prevention Policies: Write** scope |
| GovCloud / EU / US-2 tenant errors | Set `FALCON_BASE_URL` in `.env` to the correct regional endpoint |
- The disable step requires explicit confirmation before any change is applied.
- No credentials are written to disk by this script; `.env` handling is
  read-only at startup.
