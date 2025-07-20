import os
import base64
import json
import datetime
import socket
import concurrent.futures
from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode
import re
import requests
import time
import pytz
import shutil
from pathlib import Path
from difflib import Differ

# === Server Remark and Flag Functions === ----------------------------------------------------

def extract_ip_from_server(server_line):
    try:
        if server_line.startswith(('vless://', 'trojan://')):
            return urlparse(server_line.split('#')[0]).hostname
        if server_line.startswith('vmess://'):
            cfg = json.loads(base64.b64decode(server_line[8:].split('#')[0]).decode())
            return cfg.get('add')
        if server_line.startswith('ss://'):
            return urlparse(server_line.split('#')[0]).hostname
    except Exception:
        pass
    return None


def get_country_code(ip):
    if not ip:
        return ''
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=5)
        if r.status_code == 200:
            cc = r.json().get('countryCode', '')
            if len(cc) == 2:
                return cc.upper()
    except Exception:
        pass
    return ''


def country_code_to_flag(cc):
    if len(cc) != 2:
        return ''
    try:
        return chr(0x1F1E6 + ord(cc[0].upper()) - 65) + chr(0x1F1E6 + ord(cc[1].upper()) - 65)
    except Exception:
        return ''


def update_server_remarks(servers):
    out = []
    for idx, srv in enumerate(servers, 1):
        base = srv.split('#')[0]
        remark = srv.split('#', 1)[1].strip() if '#' in srv else ''
        ip = extract_ip_from_server(srv)
        flag = country_code_to_flag(get_country_code(ip))
        if '---' in remark:
            _, custom = remark.split('---', 1)
            new_remark = f"Server {idx} {flag}--- {custom.strip()}"
        else:
            new_remark = f"Server {idx} {flag}"
        out.append(f"{base}#{new_remark}")
        time.sleep(0.1)
    return out


# === Global constants / helpers --------------------------------------------------------------

USER_LIST_FILE = 'user_list.txt'
BLOCKED_SYMBOL = '🚫'
IRAN_TZ = pytz.timezone('Asia/Tehran')

LAST_USER_STATE_FILE = 'last_user_state.json'   # manual-change detector
NON_WORKING_FILE = 'non_working.txt'
MAIN_FILE = 'servers.txt'
HISTORY_FILE = 'server_history.txt'
USER_HISTORY_FILE = 'user_history.txt'

QUARANTINE_DAYS = 3
USER_HISTORY_DAYS = 7
BACKUP_DAYS = 7
SERVER_HISTORY_DAYS = 7
VALIDATION_TIMEOUT = 3
FAST_RUN = os.getenv("FAST_RUN", "0") == "1"    # skip heavy tasks if set


def get_iran_time():
    return datetime.datetime.now(pytz.UTC).astimezone(IRAN_TZ)


# === Load / save helpers ---------------------------------------------------------------------

def load_user_list():
    if not os.path.exists(USER_LIST_FILE):
        return []
    with open(USER_LIST_FILE, encoding='utf-8') as f:
        return [ln.strip() for ln in f if ln.strip()]


def save_user_list(users):
    backup_user_list()
    with open(USER_LIST_FILE, 'w', encoding='utf-8') as f:
        if users:
            f.write('\n'.join(users) + '\n')


# === Parsing helpers (username, notes, etc.) -------------------------------------------------

def extract_username_from_line(line):
    clean = line.replace(BLOCKED_SYMBOL, '').strip()
    if '#' in clean:
        clean = clean.split('#')[0].strip()
    if '---' in clean:
        clean = clean.split('---')[0].strip()
    return clean.split()[0] if clean.split() else clean


def extract_user_data_from_line(line):
    clean = line.replace(BLOCKED_SYMBOL, '').strip()
    if '---' in clean:
        clean = clean.split('---')[0].strip()
    parts = clean.split()
    return ' '.join(parts[1:]) if len(parts) > 1 else ''


def extract_notes_from_line(line):
    return line.split('#', 1)[1].strip() if '#' in line else ''


def remove_notes_from_line(line):
    return line.split('#')[0].strip() if '#' in line else line.strip()


# === Relative-time parsing / expiry helpers --------------------------------------------------

REL_PATTERNS = [
    r'^(\d{1,2}):(\d{1,2})$',
    r'(\d+)\s*(days?|d)\s+(\d{1,2}):(\d{1,2})',
    r'(\d+)\s*(days?|d)$',
    r'(\d+)\s*(weeks?|w)\s+(\d{1,2}):(\d{1,2})',
    r'(\d+)\s*(weeks?|w)$',
    r'(\d+)\s*(months?|m)\s+(\d{1,2}):(\d{1,2})',
    r'(\d+)\s*(months?|m)$',
    r'(\d+)\s*(hours?|h)$',
]


def parse_relative_datetime(txt):
    if not txt:
        return None
    now = get_iran_time()
    today = now.date()
    for i, pat in enumerate(REL_PATTERNS):
        m = re.match(pat, txt.strip(), re.I)
        if not m:
            continue
        g = m.groups()
        if i == 0:
            h, mnt = map(int, g)
            if 0 <= h <= 23 <= 59 >= mnt:
                dt = IRAN_TZ.localize(datetime.datetime.combine(today, datetime.time(h, mnt)))
                if dt <= now:
                    dt += datetime.timedelta(days=1)
                return dt
        else:
            amt = int(g[0])
            unit = g[1].lower()
            delta = (
                datetime.timedelta(days=amt) if unit.startswith('d') else
                datetime.timedelta(weeks=amt) if unit.startswith('w') else
                datetime.timedelta(days=30 * amt) if unit.startswith('m') else
                datetime.timedelta(hours=amt)
            )
            if len(g) >= 4 and g[2] and g[3]:
                h, mnt = int(g[2]), int(g[3])
            else:
                h, mnt = 23, 59
            dt = IRAN_TZ.localize(datetime.datetime.combine((now + delta).date(), datetime.time(h, mnt)))
            return dt
    return None


def format_expiry_datetime(dt):
    if not dt:
        return ''
    now = get_iran_time()
    return f"{dt.strftime('%H:%M')} expires today" if dt.date() == now.date() else f"{dt.strftime('%Y-%m-%d %H:%M')} expires"


def check_expiry_datetime(line):
    now = get_iran_time()
    for pat in [r'(\d{4}-\d{2}-\d{2} \d{1,2}:\d{2}) expires', r'(\d{1,2}:\d{2}) expires today']:
        m = re.search(pat, line)
        if not m:
            continue
        ts = m.group(1)
        try:
            if 'expires today' in line:
                h, mnt = map(int, ts.split(':'))
                dt = IRAN_TZ.localize(datetime.datetime.combine(now.date(), datetime.time(h, mnt)))
            else:
                dt = IRAN_TZ.localize(datetime.datetime.strptime(ts, '%Y-%m-%d %H:%M'))
            return dt <= now, dt
        except Exception:
            pass
    return False, None


# === Username generation / backups / history -------------------------------------------------

# ....  original helper functions unchanged  ....

# (all backup/history helpers stay as in your file – omitted here for brevity)

# === MAIN COMMAND PROCESSOR (only modified parts shown) --------------------------------------

def process_user_commands():
    users = load_user_list()
    updated_users = []
    blocked_users, unblocked_users, deleted_users = set(), set(), set()
    renamed_users, modified_users, users_to_top = {}, set(), set()
    any_commands_processed = False

    for line in users:
        # --- BLOCK ---------------------------------------------------------------------------
        if '---b' in line:
            any_commands_processed = True
            uname = extract_username_from_line(line)
            cleaned_line = line.split('---')[0].split('|')[0].strip()
            user_data = extract_user_data_from_line(cleaned_line)
            note = extract_notes_from_line(line)
            blocked_users.add(uname)
            modified_users.add(uname)
            users_to_top.add(uname)

            # compose block-date note
            block_date = get_iran_time().strftime('%Y-%m-%d')
            date_note = f"| blocked {block_date}"
            if date_note not in note:
                note = f"{note} {date_note}".strip() if note else date_note

            # LOG
            log_user_history(uname, "blocked", date_note)

            # --- FIX: re-insert ‘#’ in front of note ---
            if user_data and note:
                updated_line = f"{BLOCKED_SYMBOL}{uname} {user_data} #{note}"
            elif user_data:
                updated_line = f"{BLOCKED_SYMBOL}{uname} {user_data}"
            elif note:
                updated_line = f"{BLOCKED_SYMBOL}{uname} #{note}"
            else:
                updated_line = f"{BLOCKED_SYMBOL}{uname}"
            updated_users.append(updated_line)

        # --- UNBLOCK (unchanged, already adds #) --------------------------------------------
        elif '---ub' in line:
            any_commands_processed = True
            uname = extract_username_from_line(line)
            user_data = extract_user_data_from_line(line)
            note = extract_notes_from_line(line)
            unblocked_users.add(uname)
            modified_users.add(uname)
            users_to_top.add(uname)
            log_user_history(uname, "unblocked", "")
            if user_data and note:
                updated_line = f"{uname} {user_data} #{note}"
            elif user_data:
                updated_line = f"{uname} {user_data}"
            elif note:
                updated_line = f"{uname} #{note}"
            else:
                updated_line = uname
            updated_users.append(updated_line)

        # --- other command branches remain unchanged (omitted for brevity) ------------------
        else:
            updated_users.append(line)

    # ... remainder of function unchanged (save_user_list, backups, etc.) ...


# === BLOCKED_USERS.TXT COMMANDS (only modified note-build parts) -----------------------------

def process_blocked_users_commands():
    blocked_file = 'blocked_users.txt'
    if not os.path.exists(blocked_file):
        return

    with open(blocked_file, encoding='utf-8') as f:
        raw_lines = [ln.rstrip() for ln in f if ln.strip()]

    # ... duplicate cleanup (unchanged) ...

    # to_block  ----------------------------------------------------------
    # when rebuilding a blocked line, put "#"
    for uname in list(to_block):
        note = to_block[uname]
        iran_date = get_iran_time().strftime("%Y-%m-%d")
        date_note = f"| blocked {iran_date}"
        if date_note not in note:
            note = f"{note} {date_note}".strip() if note else date_note
        to_block[uname] = note  # update

    # ... iterate users, build updated_users list ...
            # inside branch that re-blocks a user:
            blocked_line = f"{BLOCKED_SYMBOL}{base_without_note}"
            if note:
                blocked_line += f" #{note}"
            elif '#' in user_line:
                blocked_line += f" #{extract_notes_from_line(user_line)}"
            updated_users.append(blocked_line)

    # ... after writing user_list, rebuild blocked_users.txt ...
    new_block_list = []
    for uname, note in to_block.items():
        entry = uname
        if note:
            entry += f" #{note}"
        new_block_list.append(entry)
    # ... append remaining keep_plain lines unchanged ...

# === remove_duplicates, server validation, etc. remain unchanged =============================

# === update_all_subscriptions() stays exactly the same =======================================

if __name__ == "__main__":
    update_all_subscriptions()
