"""
DCSS Change Management Analyzer  v1
=====================================
Run  :  python change_analyzer.py
Open :  http://localhost:5051

100% OFFLINE — no internet required.
All charts generated server-side with matplotlib (no Chart.js CDN).
No Google Fonts CDN — uses system fonts only.
Single file, no external assets needed.

Data columns expected (fuzzy-matched):
  Change_No, Change_Description, Change_Coordinator, CR_Assignee_Group,
  ChangeStatus, Scheduled_Start_Date, Scheduled_End_Date,
  Task_ID, Task_Scheduled_Start_Date, Task_Scheduled_End_Date,
  Task_Actual_Start_Date, Task_Actual_End_Date, Task_Assignee_Group

Designed by aawasthi
"""

import io, json, warnings, logging, re, difflib, base64
import os, secrets, hashlib
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
import pandas as pd
import numpy as np
from flask import (Flask, request, render_template_string, jsonify,
                   session, redirect, make_response)
from werkzeug.security import generate_password_hash, check_password_hash

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
#  MULTI-USER AUTH
# ═══════════════════════════════════════════════════════════════════════════════
_USERS_FILE = Path("cr_users.json")
_ENV_FILE   = Path("cr.env")
_AUDIT_FILE = Path("cr_audit.log")
_KEY_FILE   = Path(".cr_flask_secret")

ALL_TABS = [
    ("ex",  "🎯 Executive Summary"),
    ("ov",  "📊 Overview"),
    ("tr",  "📈 Monthly Trends"),
    ("chg", "📋 Changes"),
    ("tsk", "🔧 Tasks"),
    ("grp", "👥 Groups"),
    ("sch", "🗓 Schedule"),
    ("nf",  "🔍 Data Info"),
]
ALL_TAB_IDS  = [t[0] for t in ALL_TABS]
DEFAULT_TABS = ["ov", "chg", "tsk"]

def _load_env():
    env = {}
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env

def _load_users():
    if _USERS_FILE.exists():
        try: return json.loads(_USERS_FILE.read_text())
        except Exception: return {}
    return {}

def _save_users(users: dict):
    _USERS_FILE.write_text(json.dumps(users, indent=2))

def _app_setup():
    if _KEY_FILE.exists():
        secret = _KEY_FILE.read_bytes()
    else:
        secret = secrets.token_bytes(32)
        _KEY_FILE.write_bytes(secret)

    users = _load_users()
    if not users:
        plain_pw = secrets.token_urlsafe(12)
        users["admin"] = {
            "password":   generate_password_hash(plain_pw),
            "role":       "admin",
            "enabled":    True,
            "tabs":       ALL_TAB_IDS,
            "full_name":  "Administrator",
            "created_at": datetime.now().isoformat(),
        }
        _save_users(users)
        log.info("=" * 62)
        log.info("  First run — default admin account created.")
        log.info("  Username : admin")
        log.info("  Password : %s", plain_pw)
        log.info("  SAVE THIS NOW — it will never be shown again.")
        log.info("=" * 62)

    if not _ENV_FILE.exists() or "SESSION_HOURS" not in _load_env():
        existing = _ENV_FILE.read_text() if _ENV_FILE.exists() else ""
        if "SESSION_HOURS" not in existing:
            with open(_ENV_FILE, "a") as f:
                f.write("\nSESSION_HOURS=4\n")
    return secret

def _audit(event: str, extra: str = ""):
    try:
        ip   = request.remote_addr if request else "—"
        line = f"{datetime.now().isoformat()} | {event:<20} | ip={ip} | {extra}\n"
        with open(_AUDIT_FILE, "a") as f:
            f.write(line)
    except Exception:
        pass

def _current_user():
    if "username" not in session: return None
    env   = _load_env()
    hours = float(env.get("SESSION_HOURS", 4))
    if hours > 0 and "last_active" in session:
        elapsed = (datetime.now() - datetime.fromisoformat(session["last_active"])).total_seconds()
        if elapsed > hours * 3600:
            session.clear(); return None
    session["last_active"] = datetime.now().isoformat()
    users = _load_users()
    user  = users.get(session["username"])
    if not user or not user.get("enabled", True):
        session.clear(); return None
    return {**user, "username": session["username"]}

def _login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _current_user():
            if request.method == "POST" or request.is_json:
                return jsonify({"error": "Session expired.", "auth": False}), 401
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper

def _admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = _current_user()
        if not u or u.get("role") != "admin":
            return jsonify({"error": "Admin access required."}), 403
        return fn(*args, **kwargs)
    return wrapper

# ═══════════════════════════════════════════════════════════════════════════════
#  MATPLOTLIB — OFFLINE SERVER-SIDE CHARTS
# ═══════════════════════════════════════════════════════════════════════════════
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as mticker

BLUE   = "#4a8cff"; RED    = "#ff4f6a"; GREEN  = "#30d988"
YELLOW = "#ffc240"; PURPLE = "#a78bfa"; CYAN   = "#22d3ee"
ORANGE = "#fb923c"
PALETTE = [BLUE, RED, GREEN, YELLOW, PURPLE, CYAN, ORANGE,
           "#f472b6", "#34d399", "#f87171", "#60a5fa", "#fbbf24"]

STATUS_COLORS = {
    "closed":      GREEN,
    "completed":   GREEN,
    "implemented": GREEN,
    "open":        YELLOW,
    "scheduled":   BLUE,
    "in progress": CYAN,
    "cancelled":   ORANGE,
    "canceled":    ORANGE,
    "failed":      RED,
    "pending":     YELLOW,
    "draft":       PURPLE,
}

def status_color(label):
    ll = str(label).strip().lower()
    if ll in STATUS_COLORS: return STATUS_COLORS[ll]
    if any(k in ll for k in ("complet","implement","closed","done")): return GREEN
    if any(k in ll for k in ("cancel","reject")): return ORANGE
    if any(k in ll for k in ("fail","error")): return RED
    if any(k in ll for k in ("sched","plan","approv")): return BLUE
    if any(k in ll for k in ("progress","active")): return CYAN
    return PURPLE

THEMES = {
    "dark":  {"BG":"#07090f","SURFACE":"#111827","BORDER":"#1e2a40","MUTED":"#7b8db0","TEXT":"#edf2ff","GRID":"#1e2a40","LEG_BG":"#111827","LEG_EDGE":"#1e2a40"},
    "light": {"BG":"#f8fafc","SURFACE":"#ffffff","BORDER":"#e2e8f0","MUTED":"#64748b","TEXT":"#0f172a","GRID":"#e2e8f0","LEG_BG":"#ffffff","LEG_EDGE":"#cbd5e1"},
}

def _apply_rc(theme_name):
    p = THEMES[theme_name]
    plt.rcParams.update({
        "figure.facecolor":p["BG"],"axes.facecolor":p["SURFACE"],
        "axes.edgecolor":p["BORDER"],"axes.labelcolor":p["MUTED"],
        "xtick.color":p["MUTED"],"ytick.color":p["MUTED"],
        "text.color":p["TEXT"],"grid.color":p["GRID"],
        "grid.linewidth":0.6,"font.family":"DejaVu Sans",
        "font.size":9,"axes.titlesize":10,"axes.titlecolor":p["TEXT"],
        "axes.titlepad":8,"legend.facecolor":p["LEG_BG"],
        "legend.edgecolor":p["LEG_EDGE"],"legend.fontsize":8,
    })
    return p

_dp = _apply_rc("dark")
BG=_dp["BG"]; SURFACE=_dp["SURFACE"]; BORDER=_dp["BORDER"]; MUTED=_dp["MUTED"]; TEXT=_dp["TEXT"]

def fig_to_b64(fig, dpi=110):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=dpi, bbox_inches="tight", facecolor=fig.get_facecolor())
    buf.seek(0)
    data = base64.b64encode(buf.read()).decode()
    plt.close(fig)
    return f"data:image/png;base64,{data}"

def img(src, alt="", cls="chart-img"):
    return f'<img src="{src}" alt="{alt}" class="{cls}"/>'

# ── chart generators ────────────────────────────────────────────────────────

def make_donut(labels, values, colors=None, title="", size=(4.5, 3.8)):
    if not labels or not values or sum(values) == 0: return None
    all_cols = colors if colors else [PALETTE[i % len(PALETTE)] for i in range(len(labels))]
    total    = sum(values)
    legend_patches = [mpatches.Patch(color=c, label=f"{l} ({v})")
                      for l, v, c in zip(labels, values, all_cols)]
    min_count = max(1, round(total * 0.015))
    render_vals = [max(v, min_count) if v > 0 else 0 for v in values]
    nz = [(v_r, c) for v_r, v_orig, c in zip(render_vals, values, all_cols) if v_orig > 0]
    if not nz: return None
    nz_render, nz_cols = zip(*nz)
    nz_orig  = [v for v in values if v > 0]
    explode  = [0.08 if v < total * 0.03 else 0 for v in nz_orig]
    fig, ax = plt.subplots(figsize=size)
    fig.patch.set_facecolor(BG); ax.set_facecolor(BG)
    ax.pie(nz_render, colors=nz_cols, startangle=90, explode=explode,
           wedgeprops=dict(width=0.55, edgecolor=BG, linewidth=2.5))
    ax.text(0, 0, str(total), ha="center", va="center",
            fontsize=16, fontweight="bold", color=TEXT)
    ax.set_title(title, color=TEXT, pad=6)
    ax.legend(handles=legend_patches, loc="lower center", bbox_to_anchor=(0.5, -0.22),
              ncol=2, framealpha=0, fontsize=7.5)
    fig.tight_layout()
    return fig_to_b64(fig)

def make_hbar(labels, values, color=BLUE, title="", xlabel="", size=(5.5, 0.45)):
    if not labels or not values: return None
    n = len(labels); h = max(2.5, n * size[1])
    fig, ax = plt.subplots(figsize=(size[0], h))
    y = range(n)
    bars = ax.barh(list(y), values, color=color, height=0.6, edgecolor=BG, linewidth=0.5)
    ax.set_yticks(list(y)); ax.set_yticklabels(labels, fontsize=8.5)
    ax.invert_yaxis(); ax.set_xlabel(xlabel, color=MUTED); ax.set_title(title, color=TEXT)
    ax.grid(axis="x", alpha=0.4); ax.spines[["top","right","left"]].set_visible(False)
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + max(values)*0.01, bar.get_y()+bar.get_height()/2,
                str(val) if isinstance(val, int) else f"{val:.1f}",
                va="center", fontsize=7.5, color=TEXT)
    fig.tight_layout()
    return fig_to_b64(fig)

def make_vbar(labels, values, colors=None, title="", ylabel="", size=(7, 3.2)):
    if not labels or not values: return None
    fig, ax = plt.subplots(figsize=size)
    x = range(len(labels))
    cols = colors if colors else [BLUE]*len(labels)
    ax.bar(list(x), values, color=cols, edgecolor=BG, linewidth=0.5, width=0.65)
    ax.set_xticks(list(x)); ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
    ax.set_ylabel(ylabel, color=MUTED); ax.set_title(title, color=TEXT)
    ax.grid(axis="y", alpha=0.4); ax.spines[["top","right"]].set_visible(False)
    fig.tight_layout()
    return fig_to_b64(fig)

def make_line(labels, values, color=BLUE, title="", ylabel="", size=(8, 3.2)):
    if not labels or not values: return None
    fig, ax = plt.subplots(figsize=size)
    ax.plot(labels, values, color=color, linewidth=2.2, marker="o",
            markersize=5, markerfacecolor=color, markeredgecolor=BG, markeredgewidth=1.5)
    ax.fill_between(range(len(labels)), values, alpha=0.12, color=color)
    ax.set_xticks(range(len(labels))); ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
    ax.set_ylabel(ylabel, color=MUTED); ax.set_title(title, color=TEXT)
    ax.grid(axis="y", alpha=0.4); ax.spines[["top","right"]].set_visible(False)
    fig.tight_layout()
    return fig_to_b64(fig)

def make_multiline(labels, series, title="", ylabel="", size=(8, 3.2)):
    if not labels or not series: return None
    fig, ax = plt.subplots(figsize=size)
    for name, vals, col in series:
        ax.plot(labels, vals, color=col, linewidth=2, marker="o",
                markersize=4, label=name, markeredgecolor=BG, markeredgewidth=1)
        ax.fill_between(range(len(labels)), vals, alpha=0.07, color=col)
    ax.set_xticks(range(len(labels))); ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
    ax.set_ylabel(ylabel, color=MUTED); ax.set_title(title, color=TEXT)
    ax.grid(axis="y", alpha=0.4); ax.spines[["top","right"]].set_visible(False)
    ax.legend(framealpha=0.2)
    fig.tight_layout()
    return fig_to_b64(fig)

def make_stacked_bar(labels, series, title="", ylabel="", size=(7, 3.5)):
    if not labels or not series: return None
    n = len(labels)
    fig, ax = plt.subplots(figsize=size)
    x = np.arange(n); bottoms = np.zeros(n)
    for name, vals, col in series:
        vals_arr = np.array(vals, dtype=float)
        ax.bar(x, vals_arr, bottom=bottoms, label=f"{name} ({int(sum(vals_arr))})",
               color=col, edgecolor=BG, linewidth=0.4, width=0.65)
        bottoms += vals_arr
    ax.set_xticks(x); ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
    ax.set_ylabel(ylabel, color=MUTED); ax.set_title(title, color=TEXT)
    ax.grid(axis="y", alpha=0.35); ax.spines[["top","right"]].set_visible(False)
    ax.legend(framealpha=0.2, fontsize=8, loc="upper right")
    fig.tight_layout()
    return fig_to_b64(fig)

# ═══════════════════════════════════════════════════════════════════════════════
#  COLUMN REGISTRY + FUZZY MATCHING
# ═══════════════════════════════════════════════════════════════════════════════
CANONICAL = {
    "Change_No":                    ["Change_No","Change No","ChangeNo","Change_Number","Change Number","CRQ","Change ID","CR No","CR Number"],
    "Change_Description":           ["Change_Description","Change Description","ChangeDesc","Change Desc","CR Description","CR Desc","Change Summary","Summary"],
    "Change_Coordinator":           ["Change_Coordinator","Change Coordinator","ChangeCoordinator","CR Coordinator","Coordinator","CR Owner","Change Owner","Change Manager"],
    "CR_Assignee_Group":            ["CR_Assignee_Group","CR Assignee Group","CRAssigneeGroup","Change Group","Change Assignee Group","CR Group","Coordinator Group","Change Coordinator Group"],
    "ChangeStatus":                 ["ChangeStatus","Change Status","Change_Status","CR Status","Status","State"],
    "Scheduled_Start_Date":         ["Scheduled Start Date","Scheduled_Start_Date","ScheduledStartDate","CR Start Date","CR Sched Start","Change Start Date","Planned Start","Start Date"],
    "Scheduled_End_Date":           ["Scheduled End Date","Scheduled_End_Date","ScheduledEndDate","CR End Date","CR Sched End","Change End Date","Planned End","End Date"],
    "Task_ID":                      ["Task_ID","Task ID","TaskID","Task No","TaskNo","Task Number","TAS","Task_No"],
    "Task_Scheduled_Start_Date":    ["Task_Scheduled_Start_Date","Task Scheduled Start Date","TaskScheduledStartDate","Task Sched Start","Task Start","Task Planned Start"],
    "Task_Scheduled_End_Date":      ["Task_Scheduled_End_Date","Task Scheduled End Date","TaskScheduledEndDate","Task Sched End","Task End","Task Planned End"],
    "Task_Actual_Start_Date":       ["Task_Actual_Start_Date","Task Actual Start Date","TaskActualStartDate","Task Actual Start","Actual Start","Task Start Actual"],
    "Task_Actual_End_Date":         ["Task_Actual_End_Date","Task Actual End Date","TaskActualEndDate","Task Actual End","Actual End","Task End Actual"],
    "Task_Assignee_Group":          ["Task_Assignee_Group","Task Assignee Group","TaskAssigneeGroup","Task Group","Assignee Group","Task Assigned Group","Task Team"],
}

_ALIAS_MAP = {}
for canon, aliases in CANONICAL.items():
    for a in aliases:
        _ALIAS_MAP[a.lower().strip()] = canon

def fuzzy_match(col_name, threshold=0.70):
    key = col_name.lower().strip()
    if key in _ALIAS_MAP: return _ALIAS_MAP[key]
    best_score, best_canon = 0, None
    for alias, canon in _ALIAS_MAP.items():
        score = difflib.SequenceMatcher(None, key, alias).ratio()
        if score > best_score:
            best_score, best_canon = score, canon
    if best_score >= threshold:
        log.info("Fuzzy matched '%s' → '%s' (%.0f%%)", col_name, best_canon, best_score*100)
        return best_canon
    return None

def normalise_columns(df):
    df.columns = [c.strip() for c in df.columns]
    rename_map, mapped = {}, set()
    for col in df.columns:
        canon = fuzzy_match(col)
        if canon and canon not in mapped:
            rename_map[col] = canon; mapped.add(canon)
    if rename_map:
        log.info("Columns mapped: %s", rename_map)
    return df.rename(columns=rename_map)

# ═══════════════════════════════════════════════════════════════════════════════
#  DATE HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
EXCEL_EPOCH = datetime(1899, 12, 30)

def excel_serial_to_dt(val):
    try:
        f = float(val)
        if f > 0: return EXCEL_EPOCH + timedelta(days=f)
    except (TypeError, ValueError): pass
    return pd.NaT

def parse_date_col(series):
    if pd.api.types.is_datetime64_any_dtype(series): return series
    # Reset index to avoid pandas "cannot assemble with duplicate keys" error
    # which occurs when series comes from a deduplicated/sliced frame with
    # non-contiguous index values.
    orig_index = series.index
    s = series.reset_index(drop=True)
    if pd.api.types.is_numeric_dtype(s):
        result = s.apply(excel_serial_to_dt)
        result.index = orig_index
        return result
    # Coerce blank / whitespace-only strings to NaN before parsing
    s_str = s.astype(str).str.strip()
    s = s.where(s_str.isin(["", "nan", "NaT", "None", "NaN"]) == False, other=None)
    # Try dd/mm/yyyy first (dayfirst=True), then mm/dd, then Excel serial
    parsed = pd.to_datetime(s, errors="coerce", dayfirst=True)
    if parsed.isna().mean() > 0.5:
        parsed = pd.to_datetime(s, errors="coerce", dayfirst=False)
    if parsed.isna().mean() > 0.5:
        parsed = s.apply(lambda v: excel_serial_to_dt(v) if pd.notna(v) else pd.NaT)
    parsed.index = orig_index
    return parsed

# ═══════════════════════════════════════════════════════════════════════════════
#  ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
CLOSED_CHANGE_STATUSES = {"closed","completed","implemented","done","finished"}
OPEN_CHANGE_STATUSES   = {"open","scheduled","in progress","pending","draft","planned","approved"}

def analyse(df_raw):
    df_full = normalise_columns(df_raw.copy())

    F = {k: k in df_full.columns for k in list(CANONICAL.keys())}
    log.info("Feature flags: %s", {k:v for k,v in F.items() if v})

    # ── Parse date columns ─────────────────────────────────────────────────────
    for dcol in ["Scheduled_Start_Date","Scheduled_End_Date",
                 "Task_Scheduled_Start_Date","Task_Scheduled_End_Date",
                 "Task_Actual_Start_Date","Task_Actual_End_Date"]:
        if dcol in df_full.columns:
            df_full[dcol] = parse_date_col(df_full[dcol])

    # ── CHANGES — deduplicate by Change_No ────────────────────────────────────
    # Raw frame has one row per TASK; changes repeat.
    # df_cr  = unique changes
    # df_all = all rows (for task-level analysis)
    df_all  = df_full.copy()
    df_all.reset_index(drop=True, inplace=True)   # prevent duplicate-key errors in date parsing
    cr_col  = "Change_No" if F["Change_No"] else df_full.columns[0]

    if F["Change_No"]:
        raw_rows = len(df_full)
        df_cr    = df_full.drop_duplicates(subset=["Change_No"], keep="first").copy()
        df_cr.reset_index(drop=True, inplace=True)   # prevent duplicate-key errors downstream
        dedup_dropped = raw_rows - len(df_cr)
        log.info("Changes dedup: %d raw rows → %d unique changes (%d task rows removed from CR view)",
                 raw_rows, len(df_cr), dedup_dropped)
    else:
        df_cr = df_full.copy()
        df_cr.reset_index(drop=True, inplace=True)
        dedup_dropped = 0

    total_changes = len(df_cr)
    total_tasks   = len(df_all[df_all["Task_ID"].notna()]) if F["Task_ID"] else len(df_all)

    # ── Month — based on Scheduled Start Date of change ───────────────────────
    date_ref_cr = None
    for dc in ["Scheduled_Start_Date","Scheduled_End_Date"]:
        if F.get(dc) and df_cr[dc].notna().any():
            date_ref_cr = dc; break

    def _safe_month_key(dt_val):
        """Return 'YYYY-MM' string from a datetime/Timestamp, or 'Unknown' on any failure."""
        try:
            if pd.isna(dt_val): return "Unknown"
            ts = pd.Timestamp(dt_val)
            if ts is pd.NaT: return "Unknown"
            return f"{ts.year:04d}-{ts.month:02d}"
        except Exception:
            return "Unknown"

    def _safe_month_label(dt_val):
        """Return 'Mon YYYY' display label, or 'Unknown'."""
        try:
            if pd.isna(dt_val): return "Unknown"
            ts = pd.Timestamp(dt_val)
            return ts.strftime("%b %Y")
        except Exception:
            return "Unknown"

    if date_ref_cr:
        df_cr["Month"]      = df_cr[date_ref_cr].apply(_safe_month_key)
        df_cr["MonthLabel"] = df_cr[date_ref_cr].apply(_safe_month_label)
        df_cr["Year"]       = df_cr["Month"].apply(lambda m: m[:4] if m != "Unknown" else "Unknown")
    else:
        df_cr["Month"] = "Unknown"; df_cr["MonthLabel"] = "Unknown"; df_cr["Year"] = "Unknown"

    # Same for tasks — use Actual Start if available, else Scheduled Start
    date_ref_task = None
    for dc in ["Task_Actual_Start_Date","Task_Scheduled_Start_Date"]:
        if F.get(dc) and df_all[dc].notna().any():
            date_ref_task = dc; break

    if date_ref_task:
        df_all["TaskMonth"]      = df_all[date_ref_task].apply(_safe_month_key)
        df_all["TaskMonthLabel"] = df_all[date_ref_task].apply(_safe_month_label)
    else:
        df_all["TaskMonth"] = "Unknown"; df_all["TaskMonthLabel"] = "Unknown"

    # ── Date range ─────────────────────────────────────────────────────────────
    date_min = date_max = "N/A"
    if date_ref_cr and df_cr[date_ref_cr].notna().any():
        date_min = df_cr[date_ref_cr].min().strftime("%d-%b-%Y")
        date_max = df_cr[date_ref_cr].max().strftime("%d-%b-%Y")

    # ── Change Status distribution ─────────────────────────────────────────────
    status_data = {}
    if F["ChangeStatus"]:
        df_cr["ChangeStatus"] = df_cr["ChangeStatus"].fillna("Unknown").astype(str)
        vc = df_cr["ChangeStatus"].value_counts()
        status_data = {str(k): int(v) for k, v in vc.items()}
        closed_ct = int(df_cr["ChangeStatus"].str.strip().str.lower()
                        .isin(CLOSED_CHANGE_STATUSES).sum())
        open_ct   = int(df_cr["ChangeStatus"].str.strip().str.lower()
                        .isin(OPEN_CHANGE_STATUSES).sum())
    else:
        closed_ct = open_ct = 0

    # ── Monthly change counts (unique changes per month) ───────────────────────
    # Cast to str and drop "Unknown"/"nan" before sorting
    # Month keys are "YYYY-MM" strings — sort lexicographically (correct for ISO format)
    _BAD = {None, "Unknown", "nan", "NaT", ""}
    months_sorted = sorted([
        str(m) for m in df_cr["Month"].unique()
        if str(m) not in _BAD and m not in _BAD
    ])
    monthly_cr_counts = []
    monthly_cr_labels = []
    for m in months_sorted:
        cnt = int((df_cr["Month"] == m).sum())
        monthly_cr_counts.append(cnt)
        # m is "YYYY-MM" — convert to "Mon YYYY" for display
        try:
            y, mo = m.split("-")
            import calendar
            lbl = f"{calendar.month_abbr[int(mo)]} {y}"
        except Exception:
            lbl = m
        monthly_cr_labels.append(lbl)

    # ── Monthly task counts ────────────────────────────────────────────────────
    months_task_sorted = sorted([
        str(m) for m in df_all["TaskMonth"].unique()
        if str(m) not in _BAD and m not in _BAD
    ])
    monthly_task_counts = []
    monthly_task_labels = []
    for m in months_task_sorted:
        cnt = int((df_all["TaskMonth"] == m).sum())
        monthly_task_counts.append(cnt)
        try:
            y, mo = m.split("-")
            import calendar
            lbl = f"{calendar.month_abbr[int(mo)]} {y}"
        except Exception:
            lbl = m
        monthly_task_labels.append(lbl)

    # ── Change Coordinator group analysis ─────────────────────────────────────
    cr_group_rows = []
    if F["CR_Assignee_Group"]:
        crg = df_cr["CR_Assignee_Group"].fillna("").astype(str).str.strip()
        df_cr["CR_Assignee_Group"] = crg.where(crg != "", "(Unassigned)").replace("", "(Unassigned)")
        for gname, gdf in df_cr.groupby("CR_Assignee_Group", dropna=False):
            coords = (gdf["Change_Coordinator"].dropna().unique().tolist()
                      if F["Change_Coordinator"] else [])
            statuses = (gdf["ChangeStatus"].fillna("Unknown").value_counts().to_dict()
                        if F["ChangeStatus"] else {})
            cr_group_rows.append({
                "group":        str(gname),
                "total":        len(gdf),
                "coordinators": sorted(set(str(c) for c in coords)),
                "statuses":     {str(k): int(v) for k, v in statuses.items()},
            })
        cr_group_rows.sort(key=lambda x: x["total"], reverse=True)

    # ── Coordinator workload ───────────────────────────────────────────────────
    coordinator_rows = []
    if F["Change_Coordinator"]:
        cc = df_cr["Change_Coordinator"].fillna("").astype(str).str.strip()
        df_cr["Change_Coordinator"] = cc.where(cc != "", "(Unknown)")
        for cname, cdf in df_cr.groupby("Change_Coordinator", dropna=False):
            grp = (cdf["CR_Assignee_Group"].mode()[0]
                   if F["CR_Assignee_Group"] and len(cdf) else "—")
            coordinator_rows.append({
                "name":   str(cname),
                "group":  str(grp),
                "total":  len(cdf),
                "months": cdf["MonthLabel"].value_counts().to_dict() if "MonthLabel" in cdf.columns else {},
            })
        coordinator_rows.sort(key=lambda x: x["total"], reverse=True)

    # ── Task Assignee Group analysis ──────────────────────────────────────────
    task_group_rows = []
    if F["Task_Assignee_Group"]:
        # Fill NaN and whitespace-only task groups (common for cancelled tasks)
        tg = df_all["Task_Assignee_Group"].fillna("").astype(str).str.strip()
        df_all["Task_Assignee_Group"] = tg.where(tg != "", "(Blank / Cancelled)").replace("", "(Unassigned — Cancelled/No Group)")
        for gname, gdf in df_all.groupby("Task_Assignee_Group", dropna=False):
            cr_nos = (gdf["Change_No"].dropna().unique().tolist()
                      if F["Change_No"] else [])
            task_group_rows.append({
                "group":          str(gname),
                "total_tasks":    len(gdf),
                "unique_changes": len(set(str(c) for c in cr_nos)),
            })
        task_group_rows.sort(key=lambda x: x["total_tasks"], reverse=True)

    # ── Top N Groups for charts ────────────────────────────────────────────────
    TOP_N = 15
    cr_grp_labels  = [r["group"] for r in cr_group_rows[:TOP_N]]
    cr_grp_vals    = [r["total"] for r in cr_group_rows[:TOP_N]]
    tsk_grp_labels = [r["group"] for r in task_group_rows[:TOP_N]]
    tsk_grp_vals   = [r["total_tasks"] for r in task_group_rows[:TOP_N]]

    # ── Schedule Duration ─────────────────────────────────────────────────────
    duration_rows = []
    if F["Scheduled_Start_Date"] and F["Scheduled_End_Date"]:
        df_cr["Duration_Hours"] = (
            (df_cr["Scheduled_End_Date"] - df_cr["Scheduled_Start_Date"])
            .dt.total_seconds() / 3600
        ).round(1)
        df_cr.loc[df_cr["Duration_Hours"] < 0, "Duration_Hours"] = np.nan
        avg_dur = round(float(df_cr["Duration_Hours"].mean()), 1) if df_cr["Duration_Hours"].notna().any() else None

        # Duration distribution buckets
        bins = [0, 2, 8, 24, 72, 168, float("inf")]
        labels_d = ["≤2h","2–8h","8–24h","1–3d","3–7d",">7d"]
        dur_counts = []
        for i in range(len(bins)-1):
            lo, hi = bins[i], bins[i+1]
            cnt = int(df_cr["Duration_Hours"].between(lo, hi, inclusive="right").sum())
            dur_counts.append(cnt)
        duration_rows = list(zip(labels_d, dur_counts))
    else:
        avg_dur = None

    # ── Task actual vs scheduled duration ─────────────────────────────────────
    avg_task_actual_dur = None
    if F["Task_Actual_Start_Date"] and F["Task_Actual_End_Date"]:
        df_all["Task_Actual_Dur_Hours"] = (
            (df_all["Task_Actual_End_Date"] - df_all["Task_Actual_Start_Date"])
            .dt.total_seconds() / 3600
        ).round(1)
        df_all.loc[df_all["Task_Actual_Dur_Hours"] < 0, "Task_Actual_Dur_Hours"] = np.nan
        avg_task_actual_dur = round(float(df_all["Task_Actual_Dur_Hours"].mean()), 1) \
                              if df_all["Task_Actual_Dur_Hours"].notna().any() else None

    # Tasks with actual data filled vs blank
    task_actual_filled = int(df_all["Task_Actual_Start_Date"].notna().sum()) if F["Task_Actual_Start_Date"] else 0
    task_actual_blank  = total_tasks - task_actual_filled

    # ── Changes per month by coordinator group (stacked bar data) ─────────────
    monthly_by_crgrp = {}
    if F["CR_Assignee_Group"] and len(months_sorted) > 0:
        top_grps = [r["group"] for r in cr_group_rows[:6]]
        for grp in top_grps:
            monthly_by_crgrp[grp] = []
            gdf = df_cr[df_cr["CR_Assignee_Group"] == grp]
            for m in months_sorted:
                monthly_by_crgrp[grp].append(int((gdf["Month"] == m).sum()))

    # ── MoM (Month-over-Month) for changes ────────────────────────────────────
    mom_data = {}
    if len(months_sorted) >= 2:
        cur_m  = months_sorted[-1]
        prev_m = months_sorted[-2]
        cur_ct = int((df_cr["Month"] == cur_m).sum())
        prv_ct = int((df_cr["Month"] == prev_m).sum())
        try:
            import calendar
            cy, cmo = cur_m.split("-");  cur_lbl  = f"{calendar.month_abbr[int(cmo)]} {cy}"
            py, pmo = prev_m.split("-"); prev_lbl = f"{calendar.month_abbr[int(pmo)]} {py}"
        except Exception:
            cur_lbl  = cur_m; prev_lbl = prev_m

        # Tasks for same months
        cur_task_ct  = int((df_all["TaskMonth"] == cur_m).sum())
        prev_task_ct = int((df_all["TaskMonth"] == prev_m).sum())

        # Status counts for cur/prev months
        def _status_ct(month, status_set):
            if not F["ChangeStatus"]: return 0
            sub = df_cr[df_cr["Month"] == month]
            return int(sub["ChangeStatus"].str.strip().str.lower().isin(status_set).sum())

        mom_data = {
            "cur_month":  cur_lbl,  "prev_month": prev_lbl,
            "cur":  {"changes": cur_ct,  "tasks": cur_task_ct,
                     "closed":  _status_ct(cur_m,  CLOSED_CHANGE_STATUSES),
                     "open":    _status_ct(cur_m,  OPEN_CHANGE_STATUSES)},
            "prev": {"changes": prv_ct,  "tasks": prev_task_ct,
                     "closed":  _status_ct(prev_m, CLOSED_CHANGE_STATUSES),
                     "open":    _status_ct(prev_m, OPEN_CHANGE_STATUSES)},
        }

    # ── Top changes by task count ──────────────────────────────────────────────
    change_task_count = []
    if F["Change_No"] and F["Task_ID"]:
        tc = df_all.groupby("Change_No")["Task_ID"].nunique().reset_index()
        tc.columns = ["Change_No","task_count"]
        tc = tc.sort_values("task_count", ascending=False).head(20)
        for _, row in tc.iterrows():
            cr_info = df_cr[df_cr["Change_No"] == row["Change_No"]]
            desc    = str(cr_info["Change_Description"].iloc[0]) if F["Change_Description"] and len(cr_info) else "—"
            coord   = str(cr_info["Change_Coordinator"].iloc[0]) if F["Change_Coordinator"] and len(cr_info) else "—"
            grp     = str(cr_info["CR_Assignee_Group"].iloc[0])  if F["CR_Assignee_Group"]  and len(cr_info) else "—"
            status  = str(cr_info["ChangeStatus"].iloc[0])       if F["ChangeStatus"]        and len(cr_info) else "—"
            change_task_count.append({
                "cr":         str(row["Change_No"]),
                "desc":       desc[:80] + ("…" if len(desc) > 80 else ""),
                "coordinator":coord,
                "group":      grp,
                "status":     status,
                "task_count": int(row["task_count"]),
            })

    # ── Monthly breakdown table (per month: unique changes + tasks) ────────────
    monthly_table = []
    all_months = sorted(set(months_sorted) | set(months_task_sorted))
    for m in all_months:
        try:
            y, mo = m.split("-")
            import calendar
            lbl = f"{calendar.month_abbr[int(mo)]} {y}"
        except Exception:
            lbl = m
        cr_cnt   = int((df_cr["Month"] == m).sum())
        task_cnt = int((df_all["TaskMonth"] == m).sum())

        # coordinator group breakdown for this month
        if F["CR_Assignee_Group"] and cr_cnt > 0:
            grp_breakdown = {
                str(k): int(v)
                for k, v in (df_cr[df_cr["Month"] == m]["CR_Assignee_Group"]
                             .value_counts().head(3).items())
                if str(k) not in ("nan", "NaT", "None")
            }
        else:
            grp_breakdown = {}

        monthly_table.append({
            "month":         lbl,
            "changes":       cr_cnt,
            "tasks":         task_cnt,
            "grp_breakdown": grp_breakdown,
        })

    # ═══ GENERATE CHARTS (dark + light) ═══════════════════════════════════════
    def _gen_charts(theme):
        global BG, SURFACE, BORDER, MUTED, TEXT
        _p = _apply_rc(theme)
        BG=_p["BG"]; SURFACE=_p["SURFACE"]; BORDER=_p["BORDER"]
        MUTED=_p["MUTED"]; TEXT=_p["TEXT"]
        c = {}

        # Monthly change count line
        if monthly_cr_labels:
            c["monthly_changes"] = make_line(
                monthly_cr_labels, monthly_cr_counts,
                color=BLUE, title="Unique Changes per Month", ylabel="Changes")

        # Monthly task count line
        if monthly_task_labels:
            c["monthly_tasks"] = make_line(
                monthly_task_labels, monthly_task_counts,
                color=CYAN, title="Tasks per Month", ylabel="Tasks")

        # Changes + Tasks dual-line
        if monthly_cr_labels and monthly_task_labels and monthly_cr_labels == monthly_task_labels:
            c["cr_task_dual"] = make_multiline(
                monthly_cr_labels,
                [("Changes", monthly_cr_counts, BLUE),
                 ("Tasks",   monthly_task_counts, CYAN)],
                title="Changes vs Tasks per Month", ylabel="Count")

        # Change status donut
        if status_data:
            sl = list(status_data.keys()); sv = list(status_data.values())
            sc = [status_color(l) for l in sl]
            c["status_donut"] = make_donut(sl, sv, colors=sc, title="Change Status Distribution")

        # CR group workload horizontal bar
        if cr_grp_labels:
            c["crgrp_bar"] = make_hbar(
                cr_grp_labels, cr_grp_vals, color=BLUE,
                title=f"Changes by Coordinator Group (Top {len(cr_grp_labels)})",
                xlabel="Unique Changes")

        # Task group workload horizontal bar
        if tsk_grp_labels:
            c["tskgrp_bar"] = make_hbar(
                tsk_grp_labels, tsk_grp_vals, color=CYAN,
                title=f"Tasks by Assignee Group (Top {len(tsk_grp_labels)})",
                xlabel="Tasks")

        # Stacked bar: changes per month by top CR groups
        if monthly_by_crgrp and monthly_cr_labels:
            grps = list(monthly_by_crgrp.keys())
            series = [(g, monthly_by_crgrp[g], PALETTE[i % len(PALETTE)])
                      for i, g in enumerate(grps)]
            c["monthly_by_crgrp"] = make_stacked_bar(
                monthly_cr_labels, series,
                title="Changes per Month by Coordinator Group", ylabel="Changes")

        # Duration distribution donut
        if duration_rows:
            dl = [r[0] for r in duration_rows if r[1] > 0]
            dv = [r[1] for r in duration_rows if r[1] > 0]
            if dl:
                c["dur_donut"] = make_donut(dl, dv, title="Change Duration Distribution")

        # Task actual completion fill rate bar
        if F["Task_Actual_Start_Date"]:
            c["task_fill"] = make_donut(
                ["Actual data filled","No actual data"],
                [task_actual_filled, task_actual_blank],
                colors=[GREEN, MUTED],
                title="Tasks — Actual Start Date Filled")

        return {k: v for k, v in c.items() if v}

    charts       = _gen_charts("dark")
    charts_light = _gen_charts("light")

    # Restore dark
    _p = _apply_rc("dark")
    BG=_p["BG"]; SURFACE=_p["SURFACE"]; BORDER=_p["BORDER"]; MUTED=_p["MUTED"]; TEXT=_p["TEXT"]

    # ── Health score (0-100) ───────────────────────────────────────────────────
    health = 100
    if total_changes < 5: health -= 20
    if not F["Scheduled_Start_Date"]: health -= 15
    if not F["Task_ID"]: health -= 15
    if not F["Change_Coordinator"]: health -= 10
    if not F["CR_Assignee_Group"]: health -= 10
    health = max(0, health)

    return {
        "total_changes":      total_changes,
        "total_tasks":        total_tasks,
        "closed_ct":          closed_ct,
        "open_ct":            open_ct,
        "date_min":           date_min,
        "date_max":           date_max,
        "health":             health,
        "avg_duration":       avg_dur,
        "avg_task_actual_dur":avg_task_actual_dur,
        "task_actual_filled": task_actual_filled,
        "task_actual_blank":  task_actual_blank,
        "status_data":        status_data,
        "monthly_cr_labels":  monthly_cr_labels,
        "monthly_cr_counts":  monthly_cr_counts,
        "monthly_task_labels":monthly_task_labels,
        "monthly_task_counts":monthly_task_counts,
        "monthly_table":      monthly_table,
        "cr_group_rows":      cr_group_rows,
        "coordinator_rows":   coordinator_rows,
        "task_group_rows":    task_group_rows,
        "change_task_count":  change_task_count,
        "mom_data":           mom_data,
        "duration_rows":      duration_rows,
        "dedup_note":         (f"Raw rows: {len(df_full):,} — Unique changes: {total_changes:,} "
                               f"({dedup_dropped:,} task rows removed for change-level dedup)."
                               if dedup_dropped else ""),
        "raw_row_count":      len(df_full),
        "detected_cols":      [c for c in df_full.columns if not c.startswith("_")],
        "feature_flags":      F,
        "charts":             charts,
        "charts_light":       charts_light,
        "date_ref_cr":        date_ref_cr or "N/A",
        "date_ref_task":      date_ref_task or "N/A",
    }

# ═══════════════════════════════════════════════════════════════════════════════
#  FLASK APP + ROUTES
# ═══════════════════════════════════════════════════════════════════════════════
app            = Flask(__name__)
app.secret_key = _app_setup()
app.config["MAX_CONTENT_LENGTH"]      = 50 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

@app.after_request
def add_cors(r):
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Requested-With"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return r

@app.errorhandler(413)
def too_large(e): return jsonify({"error": "File too large — maximum 50 MB."}), 413

@app.errorhandler(Exception)
def handle_exc(e):
    log.exception("Unhandled"); return jsonify({"error": f"Server error: {e}"}), 500

# ─────────────────────────────────────────────────────────────────────────────
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>DCSS Change Analyzer — Sign In</title>
<style>
:root,[data-theme="dark"]{--bg:#07090f;--card:#111827;--border:#1e2a40;--text:#edf2ff;
  --muted:#7b8db0;--blue:#4a8cff;--red:#ff4f6a;--green:#30d988;--dim:#3a4b6b}
[data-theme="light"]{--bg:#f0f4f8;--card:#ffffff;--border:#cbd5e1;--text:#0f172a;
  --muted:#475569;--blue:#2563eb;--red:#dc2626;--green:#16a34a;--dim:#94a3b8}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;
  min-height:100vh;display:flex;flex-direction:column;align-items:center;
  justify-content:center;
  background-image:radial-gradient(ellipse 70% 50% at 50% 30%,rgba(74,140,255,.07),transparent 70%)}
.card{background:var(--card);border:1px solid var(--border);border-radius:18px;
  padding:40px 36px;width:100%;max-width:400px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--blue),#a78bfa,var(--green))}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:28px;justify-content:center}
.brand-icon{width:36px;height:36px;border-radius:9px;
  background:linear-gradient(135deg,var(--blue),#a78bfa);
  display:flex;align-items:center;justify-content:center;font-size:17px}
.brand-name{font-size:1rem;font-weight:800;letter-spacing:-.02em}
.brand-name span{color:var(--blue)}
h2{font-size:1.05rem;font-weight:700;margin-bottom:4px;text-align:center}
.sub{font-size:.77rem;color:var(--muted);margin-bottom:24px;text-align:center}
label{font-size:.72rem;font-weight:700;color:var(--muted);display:block;
  margin-bottom:5px;text-transform:uppercase;letter-spacing:.06em}
input{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:9px;
  padding:10px 14px;color:var(--text);font-family:inherit;font-size:.9rem;
  outline:none;margin-bottom:16px;transition:border-color .2s}
input:focus{border-color:var(--blue)}
.btn{width:100%;background:linear-gradient(135deg,var(--blue),#a78bfa);border:none;
  color:#fff;padding:12px;border-radius:11px;font-size:.9rem;font-weight:700;
  cursor:pointer;font-family:inherit;transition:opacity .15s}
.btn:hover{opacity:.88}
.err{background:rgba(255,79,106,.1);border:1px solid rgba(255,79,106,.3);
  color:var(--red);border-radius:8px;padding:9px 13px;font-size:.8rem;margin-bottom:14px}
.footer{margin-top:16px;font-size:.67rem;color:var(--dim);text-align:center}
.theme-btn{position:fixed;top:14px;right:14px;background:var(--card);border:1px solid var(--border);
  color:var(--muted);padding:6px 12px;border-radius:8px;cursor:pointer;font-size:.75rem;font-family:inherit}
</style>
</head>
<body>
<button class="theme-btn" onclick="toggleTheme()">☀ / ☾</button>
<div class="card">
  <div class="brand">
    <div class="brand-icon">📋</div>
    <div class="brand-name">DCSS <span>Change</span> Analyzer</div>
  </div>
  <h2>Sign In</h2>
  <p class="sub">ITIL Change Management Analytics</p>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="post">
    <label>Username</label>
    <input type="text" name="username" autocomplete="username" autofocus placeholder="username"/>
    <label>Password</label>
    <input type="password" name="password" autocomplete="current-password" placeholder="••••••••"/>
    <button type="submit" class="btn">Sign In →</button>
  </form>
  <p class="footer">🔌 100% Offline · No internet required</p>
</div>
<script>
function toggleTheme(){
  const h=document.documentElement;
  h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';
}
</script>
</body>
</html>"""

@app.route("/login", methods=["GET","POST"])
def login():
    if _current_user(): return redirect("/")
    error = ""
    if request.method == "POST":
        username = request.form.get("username","").strip().lower()
        password = request.form.get("password","")
        users    = _load_users()
        user     = users.get(username)
        if user and user.get("enabled", True) and check_password_hash(user["password"], password):
            session.clear()
            session["username"]    = username
            session["last_active"] = datetime.now().isoformat()
            _audit("LOGIN_SUCCESS", f"user={username}")
            return redirect("/")
        else:
            _audit("LOGIN_FAILED", f"user={username}")
            error = "Incorrect username or password."
    return render_template_string(LOGIN_PAGE, error=error)

@app.route("/logout")
def logout():
    username = session.get("username","unknown")
    _audit("LOGOUT", f"user={username}")
    session.clear()
    return redirect("/login")

@app.route("/")
@_login_required
def index():
    u       = _current_user()
    allowed = u.get("tabs", DEFAULT_TABS) if u else DEFAULT_TABS
    if u and u.get("role") == "admin": allowed = ALL_TAB_IDS
    return render_template_string(PAGE,
        username=u["username"] if u else "—",
        full_name=u.get("full_name","") if u else "",
        role=u.get("role","user") if u else "user",
        allowed_tabs=json.dumps(allowed),
        all_tabs=json.dumps(ALL_TABS))

@app.route("/upload", methods=["POST","OPTIONS"])
@_login_required
def upload():
    if request.method == "OPTIONS": return jsonify({}), 200
    username = session.get("username","—")
    if "file" not in request.files:
        return jsonify({"error": "No file received."}), 400
    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"error": "No file selected."}), 400
    fname = f.filename.lower().strip()
    _audit("FILE_UPLOAD", f"user={username} file={f.filename}")
    try: fb = io.BytesIO(f.read())
    except Exception as e: return jsonify({"error": f"Could not receive file: {e}"}), 400
    df = None
    try:
        if fname.endswith(".xlsx"):
            df = pd.read_excel(fb, engine="openpyxl")
        elif fname.endswith(".xls"):
            try:
                import xlrd; df = pd.read_excel(fb, engine="xlrd")
            except ImportError:
                try: fb.seek(0); df = pd.read_excel(fb, engine="openpyxl")
                except: return jsonify({"error":".xls needs xlrd — resave as .xlsx"}), 400
        elif fname.endswith(".csv"):
            df = pd.read_csv(fb)
        else:
            return jsonify({"error": f"Unsupported type. Use .xlsx .xls .csv"}), 400
    except Exception as e:
        return jsonify({"error": f"Could not parse file: {e}"}), 400
    if df is None or df.empty:
        return jsonify({"error": "File is empty or has no readable data."}), 400
    log.info("Read OK — %d rows, cols: %s", len(df), list(df.columns)[:10])
    try:
        result = analyse(df)
        log.info("Analysis done — changes:%d tasks:%d health:%d charts:%d",
                 result["total_changes"], result["total_tasks"],
                 result["health"], len(result["charts"]))
    except Exception as e:
        log.exception("Analysis failed"); return jsonify({"error": f"Analysis failed: {e}"}), 500
    return jsonify(result)

# ── Admin routes (minimal — mirrors incident analyzer pattern) ────────────────
@app.route("/admin/users", methods=["GET"])
@_login_required
@_admin_required
def admin_list_users():
    users = _load_users()
    safe  = [{"username":un,"full_name":u.get("full_name",""),"role":u.get("role","user"),
              "enabled":u.get("enabled",True),"tabs":u.get("tabs",DEFAULT_TABS),
              "created_at":u.get("created_at","")} for un,u in users.items()]
    safe.sort(key=lambda x:(x["role"]!="admin",x["username"]))
    return jsonify({"users":safe,"all_tabs":ALL_TABS,"default_tabs":DEFAULT_TABS})

@app.route("/admin/users", methods=["POST"])
@_login_required
@_admin_required
def admin_create_user():
    data=request.get_json() or {}
    username=data.get("username","").strip().lower(); password=data.get("password","").strip()
    if not username or not password: return jsonify({"error":"Username and password required."}),400
    if len(password)<6: return jsonify({"error":"Password must be ≥6 chars."}),400
    users=_load_users()
    if username in users: return jsonify({"error":f"User '{username}' already exists."}),409
    role=data.get("role","user"); tabs=data.get("tabs",DEFAULT_TABS)
    valid_tabs=[t for t in tabs if t in ALL_TAB_IDS]
    if role=="admin": valid_tabs=ALL_TAB_IDS
    users[username]={"password":generate_password_hash(password),"role":role,"enabled":True,
                     "tabs":valid_tabs,"full_name":data.get("full_name","").strip(),
                     "created_at":datetime.now().isoformat()}
    _save_users(users); _audit("USER_CREATED",f"by={session.get('username')} new={username}")
    return jsonify({"ok":True,"message":f"User '{username}' created."})

@app.route("/admin/users/<uname>", methods=["PATCH"])
@_login_required
@_admin_required
def admin_update_user(uname):
    data=request.get_json() or {}; users=_load_users()
    if uname not in users: return jsonify({"error":"User not found."}),404
    if "password" in data and data["password"]:
        users[uname]["password"]=generate_password_hash(data["password"])
    for k in ("enabled","full_name","role","tabs"):
        if k in data:
            if k=="tabs" and isinstance(data[k],list):
                users[uname][k]=[t for t in data[k] if t in ALL_TAB_IDS]
            else:
                users[uname][k]=data[k]
    _save_users(users); return jsonify({"ok":True})

@app.route("/admin/users/<uname>", methods=["DELETE"])
@_login_required
@_admin_required
def admin_delete_user(uname):
    if uname==session.get("username"): return jsonify({"error":"Cannot delete own account."}),400
    users=_load_users()
    if uname not in users: return jsonify({"error":"User not found."}),404
    del users[uname]; _save_users(users); _audit("USER_DELETED",f"deleted={uname}")
    return jsonify({"ok":True})

@app.route("/admin/change-password", methods=["POST"])
@_login_required
def change_own_password():
    data=request.get_json() or {}
    cur_pw=data.get("current_password",""); new_pw=data.get("new_password","")
    if len(str(new_pw))<6: return jsonify({"error":"New password must be ≥6 chars."}),400
    users=_load_users(); username=session.get("username"); user=users.get(username)
    if not user or not check_password_hash(user["password"],cur_pw):
        return jsonify({"error":"Current password incorrect."}),400
    users[username]["password"]=generate_password_hash(new_pw)
    _save_users(users); return jsonify({"ok":True,"message":"Password changed."})

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN PAGE TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════
PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>DCSS Change Analyzer</title>
<style>
/* ── DARK THEME (default) ── */
:root,[data-theme="dark"]{
  --bg:#07090f;--surf:#0d111e;--card:#111827;--card2:#161e30;
  --border:#1e2a40;--border2:#263047;
  --blue:#4a8cff;--red:#ff4f6a;--green:#30d988;--yellow:#ffc240;
  --purple:#a78bfa;--cyan:#22d3ee;--orange:#fb923c;
  --text:#edf2ff;--muted:#7b8db0;--dim:#3a4b6b;
  --hdr-bg:rgba(7,9,15,.96);--spin-bg:rgba(7,9,15,.88);
}
/* ── LIGHT THEME ── */
[data-theme="light"]{
  --bg:#f0f4f8;--surf:#e2e8f0;--card:#ffffff;--card2:#f8fafc;
  --border:#cbd5e1;--border2:#94a3b8;
  --blue:#2563eb;--red:#dc2626;--green:#16a34a;--yellow:#d97706;
  --purple:#7c3aed;--cyan:#0891b2;--orange:#ea580c;
  --text:#0f172a;--muted:#475569;--dim:#94a3b8;
  --hdr-bg:rgba(240,244,248,.97);--spin-bg:rgba(240,244,248,.92);
}
[data-theme="light"] .tabs{background:var(--surf)}
[data-theme="light"] .cc,[data-theme="light"] .kpi,
[data-theme="light"] .grp-panel,[data-theme="light"] .ucard{background:var(--card);border-color:var(--border)}
[data-theme="light"] .grp-hdr{background:var(--card2)}
[data-theme="light"] .drop{background:var(--card2);border-color:var(--border2)}
[data-theme="light"] .drop:hover,[data-theme="light"] .drop.drag{background:rgba(37,99,235,.06);border-color:var(--blue)}
[data-theme="light"] .new-btn{background:var(--card);border-color:var(--border)}
[data-theme="light"] thead th{background:var(--surf)}
[data-theme="light"] tbody tr:hover td{background:rgba(37,99,235,.04)}
[data-theme="light"] .search-box{background:var(--card);border-color:var(--border2);color:var(--text)}
[data-theme="light"] .fmt{background:var(--surf);border-color:var(--border);color:var(--muted)}
[data-theme="light"] .grp-body{background:var(--card)}
[data-theme="light"] #upload-section{background:radial-gradient(ellipse 70% 50% at 50% 30%,rgba(37,99,235,.07),transparent 70%)}
[data-theme="light"] .offline-badge{background:rgba(22,163,74,.1);border-color:rgba(22,163,74,.3);color:var(--green)}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,'Segoe UI',sans-serif;min-height:100vh}
.hdr{position:sticky;top:0;z-index:500;background:var(--hdr-bg);
  border-bottom:1px solid var(--border);padding:12px 26px;
  display:flex;align-items:center;justify-content:space-between}
.brand{display:flex;align-items:center;gap:10px}
.brand-icon{width:32px;height:32px;border-radius:8px;
  background:linear-gradient(135deg,var(--blue),var(--purple));
  display:flex;align-items:center;justify-content:center;font-size:15px}
.brand-name{font-size:.92rem;font-weight:800;letter-spacing:-.02em}
.brand-name span{color:var(--blue)}
.hdr-right{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.pill{background:var(--card);border:1px solid var(--border);padding:3px 10px;border-radius:18px;
  font-size:.65rem;color:var(--muted);font-family:monospace}
.pill.live{border-color:var(--green);color:var(--green)}
.dot{width:6px;height:6px;border-radius:50%;background:var(--green);
  box-shadow:0 0 6px var(--green);display:inline-block;margin-right:4px;animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
.health-pill{display:flex;align-items:center;gap:5px;background:var(--card);
  border:1px solid var(--border);padding:3px 10px;border-radius:18px;font-size:.67rem;font-weight:700}
#upload-section{display:flex;flex-direction:column;align-items:center;justify-content:center;
  min-height:calc(100vh - 58px);padding:40px 20px;
  background:radial-gradient(ellipse 70% 50% at 50% 30%,rgba(74,140,255,.07),transparent 70%)}
.ucard{width:100%;max-width:580px;background:var(--card);border:1px solid var(--border);
  border-radius:18px;padding:40px 36px;text-align:center;position:relative;overflow:hidden}
.ucard::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--blue),var(--purple),var(--cyan))}
.u-title{font-size:1.5rem;font-weight:800;letter-spacing:-.03em;margin-bottom:6px}
.u-title span{color:var(--blue)}
.u-sub{color:var(--muted);font-size:.83rem;margin-bottom:24px;line-height:1.65}
.offline-badge{display:inline-flex;align-items:center;gap:5px;background:rgba(48,217,136,.1);
  border:1px solid rgba(48,217,136,.3);color:var(--green);padding:4px 12px;border-radius:20px;
  font-size:.72rem;font-weight:700;margin-bottom:18px}
.drop{border:2px dashed var(--border2);border-radius:12px;padding:34px 20px;cursor:pointer;
  transition:all .2s;position:relative;background:var(--card2)}
.drop:hover,.drop.drag{border-color:var(--blue);background:rgba(74,140,255,.06)}
.drop input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.fmts{margin-top:8px;display:flex;gap:6px;justify-content:center}
.fmt{background:var(--surf);border:1px solid var(--border);padding:2px 9px;border-radius:5px;
  font-size:.65rem;font-family:monospace;color:var(--muted)}
.ubtn{margin-top:18px;background:linear-gradient(135deg,var(--blue),var(--purple));border:none;
  color:#fff;padding:12px 32px;border-radius:11px;font-size:.9rem;font-weight:700;cursor:pointer;
  font-family:inherit;transition:opacity .2s,transform .15s;width:100%}
.ubtn:hover{opacity:.9;transform:translateY(-1px)}
.ubtn:disabled{opacity:.38;cursor:not-allowed;transform:none}
.fname{margin-top:9px;font-size:.75rem;color:var(--green);font-family:monospace}
.alert-box{background:rgba(255,79,106,.1);border:1px solid rgba(255,79,106,.3);
  border-radius:9px;padding:11px 14px;color:var(--red);font-size:.82rem;margin-top:10px}
#spin{display:none;position:fixed;inset:0;background:var(--spin-bg);z-index:900;
  align-items:center;justify-content:center;flex-direction:column;gap:12px}
#spin.show{display:flex}
.spinner{width:44px;height:44px;border:3px solid var(--border2);border-top-color:var(--blue);
  border-radius:50%;animation:rot .8s linear infinite}
.spin-msg{color:var(--text);font-size:.92rem;font-weight:600}
.spin-sub{color:var(--muted);font-size:.82rem;margin-top:4px}
@keyframes rot{to{transform:rotate(360deg)}}
#dash{display:none}#dash.show{display:block}
.new-btn{display:inline-flex;align-items:center;gap:7px;background:var(--card);
  border:1px solid var(--border);color:var(--muted);padding:8px 16px;border-radius:9px;
  cursor:pointer;font-family:inherit;font-size:.78rem;font-weight:600;transition:all .2s;
  margin:14px 26px 0}
.new-btn:hover{border-color:var(--blue);color:var(--blue)}
.tabs{background:var(--surf);border-bottom:1px solid var(--border);padding:0 26px;
  display:flex;gap:2px;overflow-x:auto;position:sticky;top:58px;z-index:400}
.tab{padding:11px 16px;cursor:pointer;font-size:.78rem;font-weight:600;color:var(--muted);
  border-bottom:2px solid transparent;transition:all .2s;white-space:nowrap;user-select:none}
.tab:hover{color:var(--text)}.tab.on{color:var(--blue);border-bottom-color:var(--blue)}
.tab-pane{display:none}.tab-pane.on{display:block}
.tab-body{padding:24px 26px;max-width:1400px;margin:0 auto}
/* KPI CARDS */
.kpi-row{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px 18px;
  position:relative;overflow:hidden}
.kpi::after{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--c,var(--blue))}
.kpi-label{font-size:.68rem;color:var(--muted);font-weight:700;text-transform:uppercase;
  letter-spacing:.06em;margin-bottom:6px}
.kpi-val{font-size:1.6rem;font-weight:800;letter-spacing:-.03em;color:var(--text)}
.kpi-sub{font-size:.7rem;color:var(--muted);margin-top:3px}
/* CHART CONTAINERS */
.cc-row{display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:16px;margin-bottom:20px}
.cc{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;overflow:hidden}
.cc-full{grid-column:1/-1}
.chart-img{width:100%;height:auto;border-radius:6px;display:block}
.cc-title{font-size:.75rem;font-weight:700;color:var(--muted);text-transform:uppercase;
  letter-spacing:.06em;margin-bottom:10px}
/* SECTION HEADINGS */
.sec-hdr{font-size:.9rem;font-weight:700;margin:22px 0 12px;color:var(--text);
  display:flex;align-items:center;gap:8px}
.sec-hdr::before{content:'';display:block;width:3px;height:14px;background:var(--blue);border-radius:2px}
/* TABLES */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.8rem}
thead th{background:var(--surf);color:var(--muted);font-size:.68rem;font-weight:700;
  text-transform:uppercase;letter-spacing:.05em;padding:9px 12px;text-align:left;
  border-bottom:1px solid var(--border);white-space:nowrap}
tbody td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top;
  color:var(--text);font-size:.8rem}
tbody tr:hover td{background:rgba(74,140,255,.04)}
.mono{font-family:monospace;font-size:.77rem}
/* GROUP PANELS */
.grp-panel{background:var(--card);border:1px solid var(--border);border-radius:12px;
  margin-bottom:12px;overflow:hidden}
.grp-hdr{background:var(--card2);padding:12px 16px;cursor:pointer;
  display:flex;align-items:center;justify-content:space-between;user-select:none}
.grp-hdr:hover{background:var(--surf)}
.grp-name{font-size:.82rem;font-weight:700;color:var(--text)}
.grp-meta{font-size:.7rem;color:var(--muted);margin-top:2px}
.grp-body{background:var(--card);padding:14px 16px;border-top:1px solid var(--border)}
.g-expand{font-size:.7rem;color:var(--muted);transition:transform .2s}
.grp-panel.open .g-expand{transform:rotate(180deg)}
.grp-panel.open .grp-body{display:block}
.grp-panel:not(.open) .grp-body{display:none}
/* CHIPS */
.chip{display:inline-block;padding:2px 9px;border-radius:12px;font-size:.67rem;font-weight:700}
.chip.c-blue{background:rgba(74,140,255,.15);color:var(--blue)}
.chip.c-green{background:rgba(48,217,136,.15);color:var(--green)}
.chip.c-red{background:rgba(255,79,106,.15);color:var(--red)}
.chip.c-yellow{background:rgba(255,194,64,.15);color:var(--yellow)}
.chip.c-purple{background:rgba(167,139,250,.15);color:var(--purple)}
.chip.c-cyan{background:rgba(34,211,238,.15);color:var(--cyan)}
.chip.c-orange{background:rgba(251,146,60,.15);color:var(--orange)}
.chip.c-muted{background:rgba(123,141,176,.12);color:var(--muted)}
/* MINI BAR */
.mbar{display:flex;height:6px;border-radius:3px;overflow:hidden;background:var(--border);margin-top:6px;min-width:60px}
.mbar-fill{height:100%;border-radius:3px}
/* SEARCH */
.search-box{background:var(--card2);border:1px solid var(--border2);border-radius:8px;
  padding:7px 12px;font-size:.8rem;font-family:inherit;color:var(--text);outline:none;
  width:100%;max-width:320px;margin-bottom:12px}
.search-box:focus{border-color:var(--blue)}
/* DATE BAR */
.date-bar{display:flex;align-items:center;gap:12px;background:var(--card);border:1px solid var(--border);
  border-radius:10px;padding:9px 16px;font-size:.75rem;margin-bottom:18px;flex-wrap:wrap}
.date-bar span{color:var(--muted)}
.date-bar strong{color:var(--text);font-family:monospace}
/* MOM TABLE */
.mom-delta{font-weight:700;font-size:.82rem}
/* STATUS DOT */
.sdot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle}
/* MODAL (admin) */
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:800;
  align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal{background:var(--card);border:1px solid var(--border);border-radius:14px;
  padding:28px 30px;width:100%;max-width:440px;position:relative}
.modal h3{font-size:.95rem;font-weight:700;margin-bottom:16px}
.modal label{font-size:.72rem;font-weight:700;color:var(--muted);display:block;
  margin-bottom:4px;text-transform:uppercase;letter-spacing:.06em}
.modal input,.modal select{width:100%;background:var(--bg);border:1px solid var(--border);
  border-radius:8px;padding:8px 12px;color:var(--text);font-family:inherit;font-size:.85rem;
  outline:none;margin-bottom:13px}
.modal input:focus,.modal select:focus{border-color:var(--blue)}
.modal-close{position:absolute;top:12px;right:16px;background:none;border:none;
  color:var(--muted);cursor:pointer;font-size:1.1rem;font-family:inherit}
.mbtn{background:linear-gradient(135deg,var(--blue),var(--purple));border:none;color:#fff;
  padding:9px 22px;border-radius:9px;font-size:.82rem;font-weight:700;cursor:pointer;font-family:inherit}
.mbtn-sec{background:var(--surf);border:1px solid var(--border);color:var(--text);
  padding:9px 22px;border-radius:9px;font-size:.82rem;font-weight:600;cursor:pointer;font-family:inherit}
.modal-err{color:var(--red);font-size:.77rem;margin-top:-8px;margin-bottom:10px}
</style>
</head>
<body>
<!-- HEADER -->
<header class="hdr">
  <div class="brand">
    <div class="brand-icon">📋</div>
    <div class="brand-name">DCSS <span>Change</span> Analyzer</div>
  </div>
  <div class="hdr-right">
    <span class="pill live" id="hdr-range" style="display:none">
      <span class="dot"></span><span id="hdr-range-txt"></span>
    </span>
    <span class="pill" id="hdr-count" style="display:none"></span>
    <div class="health-pill" id="hdr-health" style="display:none">
      <span id="health-icon">●</span>
      <span id="health-score"></span>
    </div>
    <span class="pill" id="hdr-user">{{ username }}{% if full_name %} · {{ full_name }}{% endif %}</span>
    {% if role == 'admin' %}
    <button class="pill" style="cursor:pointer;border-color:var(--purple);color:var(--purple)"
            onclick="openAdmin()">⚙ Admin</button>
    {% endif %}
    <button class="pill" style="cursor:pointer" onclick="toggleTheme()">☀/☾</button>
    <a href="/logout" class="pill" style="text-decoration:none;cursor:pointer">Sign Out</a>
  </div>
</header>

<!-- SPINNER -->
<div id="spin">
  <div class="spinner"></div>
  <div class="spin-msg">Analysing your change data…</div>
  <div class="spin-sub">Deduplicating changes · Building charts · Computing metrics</div>
</div>

<!-- UPLOAD SECTION -->
<div id="upload-section">
  <div class="ucard">
    <div class="u-title">Change <span>Analyzer</span></div>
    <p class="u-sub">Upload your ITIL Change Management data (Excel or CSV).<br>
      Handles Change_No, Task_ID, coordinator groups, schedules &amp; more.</p>
    <div class="offline-badge">🔌 100% Offline — No internet required</div>
    <div class="drop" id="drop-zone">
      <input type="file" id="file-inp" accept=".xlsx,.xls,.csv"/>
      <div style="font-size:2rem;margin-bottom:8px">📂</div>
      <div style="font-weight:700;margin-bottom:4px">Drop your file here</div>
      <div style="font-size:.78rem;color:var(--muted)">or click to browse</div>
      <div class="fmts">
        <span class="fmt">.xlsx</span><span class="fmt">.xls</span><span class="fmt">.csv</span>
      </div>
    </div>
    <div class="fname" id="fname"></div>
    <div class="alert-box" id="err-box" style="display:none"></div>
    <button class="ubtn" id="upload-btn" disabled onclick="doUpload()">Analyse Changes →</button>
  </div>
</div>

<!-- DASHBOARD -->
<div id="dash">
  <button class="new-btn" onclick="resetApp()">← Upload New File</button>
  <nav class="tabs" id="tabs-nav"></nav>

  <!-- EXECUTIVE SUMMARY -->
  <div class="tab-pane" id="pane-ex">
    <div class="tab-body">
      <div class="sec-hdr">Executive Summary</div>
      <div class="date-bar" id="ex-datebar"></div>
      <div class="kpi-row" id="ex-kpis"></div>
      <!-- MoM comparison -->
      <div id="ex-mom" style="display:none">
        <div class="sec-hdr">Month-over-Month</div>
        <div class="tbl-wrap">
          <table>
            <thead>
              <tr>
                <th>Metric</th>
                <th id="mom-th-cur"></th>
                <th id="mom-th-prev"></th>
                <th>Δ MoM</th>
              </tr>
            </thead>
            <tbody id="mom-tbody"></tbody>
          </table>
        </div>
      </div>
      <div class="cc-row" style="margin-top:16px" id="ex-charts"></div>
    </div>
  </div>

  <!-- OVERVIEW -->
  <div class="tab-pane" id="pane-ov">
    <div class="tab-body">
      <div class="sec-hdr">Overview</div>
      <div class="kpi-row" id="ov-kpis"></div>
      <div class="cc-row" id="ov-charts"></div>
    </div>
  </div>

  <!-- MONTHLY TRENDS -->
  <div class="tab-pane" id="pane-tr">
    <div class="tab-body">
      <div class="sec-hdr">Monthly Trends</div>
      <div class="cc-row" id="tr-charts"></div>
      <div class="sec-hdr" style="margin-top:8px">Monthly Breakdown Table</div>
      <div class="tbl-wrap">
        <table id="monthly-table">
          <thead>
            <tr>
              <th>#</th><th>Month</th><th>Unique Changes</th><th>Tasks</th>
              <th>Top Coordinator Groups</th>
            </tr>
          </thead>
          <tbody id="monthly-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- CHANGES TAB -->
  <div class="tab-pane" id="pane-chg">
    <div class="tab-body">
      <div class="sec-hdr">Changes by Coordinator Group</div>
      <input class="search-box" id="chg-search" placeholder="Search group or coordinator…" oninput="filterGroups()"/>
      <div id="chg-groups"></div>

      <div class="sec-hdr" style="margin-top:24px">Top Changes by Task Count</div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr><th>Change No</th><th>Description</th><th>Coordinator</th>
                <th>Group</th><th>Status</th><th>Tasks</th></tr>
          </thead>
          <tbody id="top-changes-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TASKS TAB -->
  <div class="tab-pane" id="pane-tsk">
    <div class="tab-body">
      <div class="sec-hdr">Tasks by Assignee Group</div>
      <input class="search-box" id="tsk-search" placeholder="Search group…" oninput="filterTaskGroups()"/>
      <div id="tsk-groups"></div>
      <div class="cc-row" style="margin-top:20px" id="tsk-charts"></div>
    </div>
  </div>

  <!-- GROUPS TAB -->
  <div class="tab-pane" id="pane-grp">
    <div class="tab-body">
      <div class="sec-hdr">Coordinator Groups — Change Load</div>
      <div class="cc-row" id="grp-charts-cr"></div>
      <div class="sec-hdr" style="margin-top:8px">Task Assignee Groups — Load</div>
      <div class="cc-row" id="grp-charts-tsk"></div>
    </div>
  </div>

  <!-- SCHEDULE TAB -->
  <div class="tab-pane" id="pane-sch">
    <div class="tab-body">
      <div class="sec-hdr">Schedule &amp; Duration Analysis</div>
      <div class="kpi-row" id="sch-kpis"></div>
      <div class="cc-row" id="sch-charts"></div>
      <div class="sec-hdr" style="margin-top:8px">Duration Distribution</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Duration Bucket</th><th>Change Count</th><th>Share</th></tr></thead>
          <tbody id="dur-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- DATA INFO -->
  <div class="tab-pane" id="pane-nf">
    <div class="tab-body">
      <div class="sec-hdr">Data Info</div>
      <div id="nf-body" style="font-size:.82rem;color:var(--muted);line-height:1.9"></div>
      <div class="sec-hdr" style="margin-top:16px">Detected Columns</div>
      <div id="col-chips" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px"></div>
      <div class="sec-hdr" style="margin-top:16px">Feature Flags</div>
      <div id="feat-flags" style="font-size:.78rem;line-height:2;color:var(--muted)"></div>
    </div>
  </div>

</div><!-- /dash -->

<!-- ADMIN MODAL -->
<div class="modal-bg" id="admin-modal">
  <div class="modal">
    <button class="modal-close" onclick="closeAdmin()">✕</button>
    <h3>⚙ Admin Panel</h3>
    <div id="admin-body" style="font-size:.82rem;color:var(--muted)">Loading…</div>
  </div>
</div>

<script>
// ── globals ──────────────────────────────────────────────────────────────────
let DATA    = null;
let THEME   = 'dark';
const ALLOWED_TABS  = {{ allowed_tabs|safe }};
const ALL_TABS_DEF  = {{ all_tabs|safe }};

// ── helpers ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
function chip(txt, cls='c-blue') {
  return `<span class="chip ${cls}">${txt}</span>`;
}
function statusChip(s) {
  const l=s.toLowerCase();
  let cls='c-blue';
  if(/complet|implement|closed|done/.test(l)) cls='c-green';
  else if(/cancel|reject/.test(l)) cls='c-orange';
  else if(/fail|error/.test(l)) cls='c-red';
  else if(/sched|plan|approv/.test(l)) cls='c-blue';
  else if(/progress|active/.test(l)) cls='c-cyan';
  else if(/open|pending|draft/.test(l)) cls='c-yellow';
  return chip(s, cls);
}
function fmt(n) { return (n||0).toLocaleString(); }
function kpiCard(label, val, sub='', color='var(--blue)') {
  return `<div class="kpi" style="--c:${color}">
    <div class="kpi-label">${label}</div>
    <div class="kpi-val">${val}</div>
    ${sub?`<div class="kpi-sub">${sub}</div>`:''}
  </div>`;
}
function chartBox(key, fullwidth=false) {
  const src = THEME==='dark' ? (DATA.charts||{})[key] : (DATA.charts_light||{})[key];
  if (!src) return '';
  return `<div class="cc${fullwidth?' cc-full':''}">
    <img src="${src}" class="chart-img" alt="${key}"/>
  </div>`;
}
function mbar(pct, color='var(--blue)') {
  return `<div class="mbar"><div class="mbar-fill" style="width:${Math.min(100,pct)}%;background:${color}"></div></div>`;
}

// ── theme ─────────────────────────────────────────────────────────────────────
function toggleTheme() {
  THEME = THEME === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = THEME;
  if (DATA) rebuildCharts();
}
function rebuildCharts() {
  // Just force re-render of current tab's charts via theme toggle
  renderAll(DATA);
}

// ── tabs ─────────────────────────────────────────────────────────────────────
function buildTabs() {
  const nav = $('tabs-nav'); nav.innerHTML = '';
  const allowed = ALLOWED_TABS;
  ALL_TABS_DEF.forEach(([id, label]) => {
    if (!allowed.includes(id)) return;
    const t = document.createElement('div');
    t.className = 'tab'; t.dataset.tab = id; t.textContent = label;
    t.onclick = () => switchTab(id);
    nav.appendChild(t);
  });
}
function switchTab(id) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('on', t.dataset.tab===id));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('on', p.id==='pane-'+id));
}
function firstAllowedTab() {
  return ALLOWED_TABS[0] || 'ov';
}

// ── upload & reset ────────────────────────────────────────────────────────────
const fileInp = $('file-inp');
fileInp.addEventListener('change', () => {
  const f = fileInp.files[0];
  if (f) { $('fname').textContent = '📄 ' + f.name; $('upload-btn').disabled = false; }
});
const dropZone = $('drop-zone');
['dragover','dragenter'].forEach(e => dropZone.addEventListener(e, ev => {
  ev.preventDefault(); dropZone.classList.add('drag');
}));
['dragleave','drop'].forEach(e => dropZone.addEventListener(e, ev => {
  ev.preventDefault(); dropZone.classList.remove('drag');
  if (e==='drop' && ev.dataTransfer.files[0]) {
    fileInp.files = ev.dataTransfer.files;
    $('fname').textContent = '📄 ' + ev.dataTransfer.files[0].name;
    $('upload-btn').disabled = false;
  }
}));

function doUpload() {
  const f = fileInp.files[0];
  if (!f) return;
  $('err-box').style.display='none';
  $('spin').classList.add('show');
  $('upload-btn').disabled = true;
  const fd = new FormData(); fd.append('file', f);
  fetch('/upload', { method:'POST', body:fd })
    .then(r => r.json())
    .then(d => {
      $('spin').classList.remove('show');
      if (d.error) { showErr(d.error); $('upload-btn').disabled=false; return; }
      DATA = d;
      $('upload-section').style.display='none';
      $('dash').classList.add('show');
      buildTabs(); switchTab(firstAllowedTab());
      renderAll(d);
    })
    .catch(e => {
      $('spin').classList.remove('show');
      showErr('Network error: '+e.message);
      $('upload-btn').disabled=false;
    });
}
function showErr(msg) {
  const b=$('err-box'); b.textContent=msg; b.style.display='block';
}
function resetApp() {
  DATA=null; fileInp.value=''; $('fname').textContent='';
  $('upload-btn').disabled=true; $('err-box').style.display='none';
  $('dash').classList.remove('show');
  document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('on'));
  $('hdr-range').style.display='none'; $('hdr-count').style.display='none';
  $('hdr-health').style.display='none';
  $('upload-section').style.display='';
}

// ── render all tabs ───────────────────────────────────────────────────────────
function renderAll(d) {
  buildHeader(d);
  buildEx(d);
  buildOv(d);
  buildTrends(d);
  buildChanges(d);
  buildTasks(d);
  buildGroups(d);
  buildSchedule(d);
  buildInfo(d);
}

// ── header ────────────────────────────────────────────────────────────────────
function buildHeader(d) {
  if (d.date_min && d.date_min!=='N/A') {
    $('hdr-range').style.display='';
    $('hdr-range-txt').textContent = d.date_min + ' – ' + d.date_max;
  }
  $('hdr-count').style.display='';
  $('hdr-count').textContent = fmt(d.total_changes)+' Changes · '+fmt(d.total_tasks)+' Tasks';
  const h=d.health||0, hpill=$('hdr-health');
  hpill.style.display='';
  $('health-icon').style.color = h>=80?'var(--green)':h>=50?'var(--yellow)':'var(--red)';
  $('health-score').textContent = 'Data: '+h+'%';
}

// ── executive summary ─────────────────────────────────────────────────────────
function buildEx(d) {
  if ($('ex-datebar') && d.date_min && d.date_min!=='N/A')
    $('ex-datebar').innerHTML =
      `<span>Date Range</span><strong>${d.date_min}</strong>
       <span>→</span><strong>${d.date_max}</strong>
       <span style="margin-left:auto">Grouped by</span>
       <strong>${d.date_ref_cr||'—'}</strong>`;

  $('ex-kpis').innerHTML =
    kpiCard('Total Changes',   fmt(d.total_changes),  d.closed_ct+' closed', 'var(--blue)')  +
    kpiCard('Total Tasks',     fmt(d.total_tasks),    '',                      'var(--cyan)')  +
    kpiCard('Closed Changes',  fmt(d.closed_ct),      '',                      'var(--green)') +
    kpiCard('Open / Active',   fmt(d.open_ct),        '',                      'var(--yellow)')+
    (d.avg_duration!=null ? kpiCard('Avg Duration', d.avg_duration+'h', 'per change', 'var(--purple)') : '') +
    (d.avg_task_actual_dur!=null ? kpiCard('Avg Task Actual', d.avg_task_actual_dur+'h', 'actual duration', 'var(--orange)') : '');

  // MoM section
  const mom = d.mom_data||{};
  if (mom.cur_month) {
    $('ex-mom').style.display='';
    $('mom-th-cur').textContent  = mom.cur_month;
    $('mom-th-prev').textContent = mom.prev_month;
    function delta(cur, prev, hib=false) {
      if (cur==null||prev==null) return '—';
      const diff=cur-prev, sign=diff>0?'+':'';
      const good=(hib&&diff>0)||(!hib&&diff<0);
      const col=good?'var(--green)':diff===0?'var(--muted)':'var(--red)';
      const arr=diff>0?'↑':diff<0?'↓':'→';
      return `<span class="mom-delta" style="color:${col}">${arr} ${sign}${diff}</span>`;
    }
    const cur=mom.cur||{}, prev=mom.prev||{};
    $('mom-tbody').innerHTML = [
      {label:'Total Changes', ck:'changes', pk:'changes', hib:false},
      {label:'Total Tasks',   ck:'tasks',   pk:'tasks',   hib:false},
      {label:'Closed Changes',ck:'closed',  pk:'closed',  hib:true },
      {label:'Open Changes',  ck:'open',    pk:'open',    hib:false},
    ].map(m=>`<tr>
      <td style="font-weight:600">${m.label}</td>
      <td class="mono" style="font-weight:700;color:var(--blue)">${fmt(cur[m.ck]??0)}</td>
      <td class="mono" style="color:var(--muted)">${fmt(prev[m.pk]??0)}</td>
      <td>${delta(cur[m.ck]??0, prev[m.pk]??0, m.hib)}</td>
    </tr>`).join('');
  }

  $('ex-charts').innerHTML =
    chartBox('monthly_changes') +
    chartBox('status_donut') +
    chartBox('monthly_by_crgrp', true);
}

// ── overview ──────────────────────────────────────────────────────────────────
function buildOv(d) {
  $('ov-kpis').innerHTML =
    kpiCard('Unique Changes',   fmt(d.total_changes),  (d.dedup_note?'deduped':'all rows'), 'var(--blue)')  +
    kpiCard('Unique Tasks',     fmt(d.total_tasks),    '',                                   'var(--cyan)')  +
    kpiCard('Coordinator Groups', fmt((d.cr_group_rows||[]).length), '', 'var(--purple)') +
    kpiCard('Task Groups',      fmt((d.task_group_rows||[]).length), '', 'var(--orange)');

  $('ov-charts').innerHTML =
    chartBox('status_donut') +
    chartBox('crgrp_bar') +
    chartBox('tskgrp_bar') +
    chartBox('cr_task_dual', true);
}

// ── trends ────────────────────────────────────────────────────────────────────
function buildTrends(d) {
  $('tr-charts').innerHTML =
    chartBox('monthly_changes') +
    chartBox('monthly_tasks') +
    chartBox('monthly_by_crgrp', true);

  const rows = d.monthly_table || [];
  const total_cr   = rows.reduce((s,r)=>s+r.changes, 0);
  const total_tsk  = rows.reduce((s,r)=>s+r.tasks, 0);
  $('monthly-tbody').innerHTML = rows.map((r,i)=>{
    const gbHtml = Object.entries(r.grp_breakdown||{}).slice(0,3)
      .map(([g,n])=>`<span class="chip c-muted" style="font-size:.63rem">${g} (${n})</span>`).join(' ');
    const crPct  = total_cr  ? r.changes/total_cr *100 : 0;
    const tskPct = total_tsk ? r.tasks/total_tsk*100 : 0;
    return `<tr>
      <td class="mono" style="color:var(--muted)">${i+1}</td>
      <td style="font-weight:600">${r.month}</td>
      <td>
        <span class="mono" style="color:var(--blue);font-weight:700">${fmt(r.changes)}</span>
        ${mbar(crPct, 'var(--blue)')}
      </td>
      <td>
        <span class="mono" style="color:var(--cyan);font-weight:700">${fmt(r.tasks)}</span>
        ${mbar(tskPct, 'var(--cyan)')}
      </td>
      <td style="font-size:.72rem">${gbHtml}</td>
    </tr>`;
  }).join('');
}

// ── changes ───────────────────────────────────────────────────────────────────
let _crGroups = [];
function buildChanges(d) {
  _crGroups = d.cr_group_rows || [];
  renderCrGroups(_crGroups);

  const rows = d.change_task_count || [];
  $('top-changes-tbody').innerHTML = rows.map(r=>`<tr>
    <td class="mono" style="color:var(--blue);font-weight:700">${r.cr}</td>
    <td style="max-width:260px;font-size:.76rem">${r.desc}</td>
    <td>${r.coordinator}</td>
    <td style="font-size:.75rem">${r.group}</td>
    <td>${statusChip(r.status)}</td>
    <td class="mono" style="font-weight:700;color:var(--cyan)">${r.task_count}</td>
  </tr>`).join('');
}
function renderCrGroups(rows) {
  const maxTotal = rows.length ? Math.max(...rows.map(r=>r.total)) : 1;
  $('chg-groups').innerHTML = rows.map(r=>{
    const pct = r.total/maxTotal*100;
    const coords = (r.coordinators||[]).map(c=>`<span class="chip c-blue" style="font-size:.68rem">${c}</span>`).join(' ');
    const statHtml = Object.entries(r.statuses||{}).map(([s,n])=>
      `<span style="margin-right:8px">${statusChip(s)} <span class="mono">${n}</span></span>`).join('');
    return `<div class="grp-panel" id="crg-${r.group.replace(/\W/g,'_')}">
      <div class="grp-hdr" onclick="this.parentElement.classList.toggle('open')">
        <div>
          <div class="grp-name">${r.group}</div>
          <div class="grp-meta">${fmt(r.total)} change${r.total!==1?'s':''}</div>
          ${mbar(pct,'var(--blue)')}
        </div>
        <span class="g-expand">▼</span>
      </div>
      <div class="grp-body">
        <div style="margin-bottom:8px;font-size:.75rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Coordinators</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:12px">${coords||'<span style="color:var(--dim)">—</span>'}</div>
        <div style="font-size:.75rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Status Breakdown</div>
        <div>${statHtml||'—'}</div>
      </div>
    </div>`;
  }).join('');
}
function filterGroups() {
  const q = $('chg-search').value.toLowerCase();
  const filtered = _crGroups.filter(r=>
    r.group.toLowerCase().includes(q) ||
    (r.coordinators||[]).some(c=>c.toLowerCase().includes(q))
  );
  renderCrGroups(filtered);
}

// ── tasks ─────────────────────────────────────────────────────────────────────
let _tskGroups = [];
function buildTasks(d) {
  _tskGroups = d.task_group_rows || [];
  renderTaskGroups(_tskGroups);
  $('tsk-charts').innerHTML =
    chartBox('tskgrp_bar') +
    chartBox('task_fill');
}
function renderTaskGroups(rows) {
  const maxTotal = rows.length ? Math.max(...rows.map(r=>r.total_tasks)) : 1;
  $('tsk-groups').innerHTML = rows.map(r=>{
    const pct = r.total_tasks/maxTotal*100;
    return `<div class="grp-panel">
      <div class="grp-hdr" onclick="this.parentElement.classList.toggle('open')">
        <div>
          <div class="grp-name">${r.group}</div>
          <div class="grp-meta">${fmt(r.total_tasks)} task${r.total_tasks!==1?'s':''} · across ${fmt(r.unique_changes)} unique change${r.unique_changes!==1?'s':''}</div>
          ${mbar(pct,'var(--cyan)')}
        </div>
        <span class="g-expand">▼</span>
      </div>
      <div class="grp-body">
        <div style="display:flex;gap:20px">
          <div>
            <div class="kpi-label">Total Tasks</div>
            <div class="kpi-val" style="font-size:1.3rem;color:var(--cyan)">${fmt(r.total_tasks)}</div>
          </div>
          <div>
            <div class="kpi-label">Unique Changes</div>
            <div class="kpi-val" style="font-size:1.3rem;color:var(--blue)">${fmt(r.unique_changes)}</div>
          </div>
        </div>
      </div>
    </div>`;
  }).join('');
}
function filterTaskGroups() {
  const q = $('tsk-search').value.toLowerCase();
  renderTaskGroups(_tskGroups.filter(r=>r.group.toLowerCase().includes(q)));
}

// ── groups ────────────────────────────────────────────────────────────────────
function buildGroups(d) {
  $('grp-charts-cr').innerHTML =
    chartBox('crgrp_bar') +
    chartBox('monthly_by_crgrp', true);
  $('grp-charts-tsk').innerHTML =
    chartBox('tskgrp_bar');
}

// ── schedule ──────────────────────────────────────────────────────────────────
function buildSchedule(d) {
  $('sch-kpis').innerHTML =
    (d.avg_duration!=null ? kpiCard('Avg Change Duration', d.avg_duration+'h','scheduled','var(--blue)') : '') +
    (d.avg_task_actual_dur!=null ? kpiCard('Avg Task Actual Dur', d.avg_task_actual_dur+'h','','var(--cyan)') : '') +
    kpiCard('Tasks with Actual', fmt(d.task_actual_filled), 'actual start date filled', 'var(--green)') +
    kpiCard('Tasks No Actual', fmt(d.task_actual_blank), 'actual start date blank', 'var(--muted)');

  $('sch-charts').innerHTML =
    chartBox('dur_donut') +
    chartBox('task_fill');

  const dur = d.duration_rows || [];
  const total_dur = dur.reduce((s,[,v])=>s+v,0);
  $('dur-tbody').innerHTML = dur.map(([lbl,cnt])=>{
    const pct = total_dur ? (cnt/total_dur*100).toFixed(1) : 0;
    return `<tr>
      <td style="font-weight:600">${lbl}</td>
      <td class="mono" style="color:var(--blue);font-weight:700">${fmt(cnt)}</td>
      <td style="width:200px">
        <span class="mono" style="color:var(--muted)">${pct}%</span>
        ${mbar(parseFloat(pct), 'var(--blue)')}
      </td>
    </tr>`;
  }).join('');
}

// ── data info ─────────────────────────────────────────────────────────────────
function buildInfo(d) {
  $('nf-body').innerHTML =
    `<b>Raw rows loaded:</b> ${fmt(d.raw_row_count)}<br>
     <b>Unique changes (deduped):</b> ${fmt(d.total_changes)}<br>
     <b>Total task rows:</b> ${fmt(d.total_tasks)}<br>
     <b>Date range used for changes:</b> ${d.date_ref_cr||'N/A'}<br>
     <b>Date range used for tasks:</b> ${d.date_ref_task||'N/A'}<br>
     <b>Date range:</b> ${d.date_min} – ${d.date_max}<br>
     ${d.dedup_note ? '<b>Dedup note:</b> '+d.dedup_note+'<br>' : ''}`;

  $('col-chips').innerHTML=(d.detected_cols||[]).map(c=>
    `<span style="background:var(--surf);border:1px solid var(--border);padding:3px 10px;
     border-radius:6px;font-size:.67rem;font-family:monospace;color:var(--muted)">${c}</span>`
  ).join('');

  const ff=d.feature_flags||{};
  $('feat-flags').innerHTML=Object.entries(ff).map(([k,v])=>
    `<div><span style="color:${v?'var(--green)':'var(--dim)'}">${v?'✓':'✗'}</span> ${k}</div>`
  ).join('');
}

// ── admin ─────────────────────────────────────────────────────────────────────
function openAdmin() {
  $('admin-modal').classList.add('show');
  fetch('/admin/users').then(r=>r.json()).then(data=>{
    const users = data.users||[];
    const allTabs = data.all_tabs||[];
    $('admin-body').innerHTML=`
      <div style="margin-bottom:14px;display:flex;gap:8px">
        <button class="mbtn" onclick="showAddUser()">+ Add User</button>
        <button class="mbtn-sec" onclick="showChangePw()">🔑 Change My Password</button>
      </div>
      <div class="tbl-wrap">
      <table>
        <thead><tr><th>Username</th><th>Full Name</th><th>Role</th><th>Status</th><th>Tabs</th><th>Actions</th></tr></thead>
        <tbody>${users.map(u=>`<tr>
          <td class="mono">${u.username}</td>
          <td>${u.full_name||'—'}</td>
          <td>${chip(u.role, u.role==='admin'?'c-purple':'c-blue')}</td>
          <td>${u.enabled?chip('Active','c-green'):chip('Disabled','c-red')}</td>
          <td style="font-size:.7rem">${(u.tabs||[]).length} tabs</td>
          <td>
            <button class="mbtn-sec" style="padding:4px 10px;font-size:.72rem"
              onclick='editUser(${JSON.stringify(u)}, ${JSON.stringify(allTabs)})'>Edit</button>
          </td>
        </tr>`).join('')}</tbody>
      </table></div>`;
  });
}
function closeAdmin(){$('admin-modal').classList.remove('show')}

function showAddUser(){
  $('admin-body').innerHTML=`
    <button class="mbtn-sec" style="margin-bottom:14px" onclick="openAdmin()">← Back</button>
    <label>Username</label><input id="nu-uname" placeholder="jsmith"/>
    <label>Full Name</label><input id="nu-fname" placeholder="John Smith"/>
    <label>Password (min 6)</label><input type="password" id="nu-pw"/>
    <label>Role</label>
    <select id="nu-role"><option value="user">User</option><option value="admin">Admin</option></select>
    <div id="nu-err" class="modal-err"></div>
    <button class="mbtn" onclick="submitAddUser()">Create User</button>`;
}
function submitAddUser(){
  const un=$('nu-uname').value.trim(), fp=$('nu-fname').value.trim();
  const pw=$('nu-pw').value, role=$('nu-role').value;
  if(!un||!pw){$('nu-err').textContent='Username and password required.';return;}
  fetch('/admin/users',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:un,full_name:fp,password:pw,role,tabs:['ov','chg','tsk']})})
    .then(r=>r.json()).then(d=>{
      if(d.error){$('nu-err').textContent=d.error;}
      else{openAdmin();}
    });
}

function editUser(u, allTabs){
  const tabCheckboxes=allTabs.map(([id,label])=>
    `<label style="display:flex;align-items:center;gap:6px;margin-bottom:4px;font-size:.8rem;color:var(--text);font-weight:400;text-transform:none;letter-spacing:0">
      <input type="checkbox" id="tab-${id}" ${(u.tabs||[]).includes(id)?'checked':''}/>
      ${label}
    </label>`).join('');
  $('admin-body').innerHTML=`
    <button class="mbtn-sec" style="margin-bottom:14px" onclick="openAdmin()">← Back</button>
    <label>Full Name</label><input id="eu-fname" value="${u.full_name||''}"/>
    <label>Role</label>
    <select id="eu-role">
      <option value="user" ${u.role==='user'?'selected':''}>User</option>
      <option value="admin" ${u.role==='admin'?'selected':''}>Admin</option>
    </select>
    <label>Status</label>
    <select id="eu-enabled">
      <option value="1" ${u.enabled?'selected':''}>Active</option>
      <option value="0" ${!u.enabled?'selected':''}>Disabled</option>
    </select>
    <label>New Password (leave blank to keep)</label><input type="password" id="eu-pw"/>
    <label style="margin-bottom:6px">Tab Access</label>
    <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:13px;max-height:200px;overflow-y:auto">${tabCheckboxes}</div>
    <div id="eu-err" class="modal-err"></div>
    <div style="display:flex;gap:8px">
      <button class="mbtn" onclick="submitEditUser('${u.username}')">Save</button>
      ${u.username!=='admin'?`<button class="mbtn-sec" style="border-color:var(--red);color:var(--red)" onclick="deleteUser('${u.username}')">Delete</button>`:''}
    </div>`;
}
function submitEditUser(uname){
  const payload={
    full_name:$('eu-fname').value.trim(),
    role:$('eu-role').value,
    enabled:$('eu-enabled').value==='1',
    tabs:[...document.querySelectorAll('[id^="tab-"]:checked')].map(c=>c.id.replace('tab-',''))
  };
  const pw=$('eu-pw').value;
  if(pw){if(pw.length<6){$('eu-err').textContent='Password must be ≥6 chars.';return;}payload.password=pw;}
  fetch('/admin/users/'+uname,{method:'PATCH',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(payload)}).then(r=>r.json()).then(d=>{
      if(d.error){$('eu-err').textContent=d.error;}else{openAdmin();}
    });
}
function deleteUser(uname){
  if(!confirm('Delete user "'+uname+'"?')) return;
  fetch('/admin/users/'+uname,{method:'DELETE'}).then(r=>r.json()).then(()=>openAdmin());
}

function showChangePw(){
  $('admin-body').innerHTML=`
    <button class="mbtn-sec" style="margin-bottom:14px" onclick="openAdmin()">← Back</button>
    <label>Current Password</label><input type="password" id="cpw-cur"/>
    <label>New Password</label><input type="password" id="cpw-new"/>
    <div id="cpw-err" class="modal-err"></div>
    <button class="mbtn" onclick="submitChangePw()">Update Password</button>`;
}
function submitChangePw(){
  const cur=$('cpw-cur').value, nw=$('cpw-new').value;
  if(!cur||!nw){$('cpw-err').textContent='Both fields required.';return;}
  if(nw.length<6){$('cpw-err').textContent='Min 6 chars.';return;}
  fetch('/admin/change-password',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({current_password:cur,new_password:nw})})
    .then(r=>r.json()).then(d=>{
      if(d.error){$('cpw-err').textContent=d.error;}
      else{alert('Password changed successfully.');closeAdmin();}
    });
}
</script>
</body>
</html>"""

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import socket, sys

    if "--set-password" in sys.argv:
        import getpass
        print("\nSet admin password — DCSS Change Analyzer")
        print("-" * 44)
        uname = input("Username to update [admin]: ").strip() or "admin"
        new_pw = getpass.getpass("New password (min 6 chars): ")
        if len(new_pw) < 6: print("Error: min 6 chars."); sys.exit(1)
        confirm = getpass.getpass("Confirm password: ")
        if new_pw != confirm: print("Error: mismatch."); sys.exit(1)
        _app_setup()
        users = _load_users()
        if uname not in users: print(f"Error: user '{uname}' not found."); sys.exit(1)
        users[uname]["password"] = generate_password_hash(new_pw)
        _save_users(users)
        print(f"✅ Password updated for '{uname}'")
        sys.exit(0)

    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(("8.8.8.8",80))
        lan_ip=s.getsockname()[0]; s.close()
    except: lan_ip="YOUR_SERVER_IP"

    port = 5051
    env  = _load_env()
    users = _load_users()
    print("\n"+"="*64)
    print("  DCSS Change Analyzer — Designed by aawasthi")
    print("="*64)
    print(f"  Local   :  http://localhost:{port}")
    print(f"  Remote  :  http://{lan_ip}:{port}")
    print("="*64)
    print("  📋 ITIL Change Management Analytics")
    print("  🔒 Login required — check above for auto-generated password")
    print(f"  👥 Users         : {len(users)} account(s) in cr_users.json")
    print(f"  ⏱  Session expiry : {env.get('SESSION_HOURS','4')} hours of inactivity")
    print(f"  📋 Audit log     : {_AUDIT_FILE.resolve()}")
    print(f"  🔑 Reset pwd     : python change_analyzer.py --set-password")
    print(f"  📖 View audit    : http://localhost:{port}/audit")
    print("  🔌 100% OFFLINE — No internet required")
    print("  Formats : .xlsx  .xls  .csv  |  Press Ctrl+C to stop")
    print("="*64+"\n")
    app.run(debug=False, port=port, host="0.0.0.0", threaded=True)
