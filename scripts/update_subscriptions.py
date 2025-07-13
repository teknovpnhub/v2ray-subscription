import os
import base64
import json
import datetime
import socket
from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode
import re
import requests
import time
import pytz

# === Server Remark and Flag Functions ===

def extract_ip_from_server(server_line):
    try:
        if server_line.startswith(('vless://', 'trojan://')):
            parsed = urlparse(server_line.split('#')[0])
            return parsed.hostname
        elif server_line.startswith('vmess://'):
            base64_part = server_line[8:].split('#')[0]
            decoded = base64.b64decode(base64_part).decode('utf-8')
            config = json.loads(decoded)
            return config.get('add')
        elif server_line.startswith('ss://'):
            parsed = urlparse(server_line.split('#')[0])
            return parsed.hostname
        return None
    except Exception:
        return None

def get_country_code(ip):
    if not ip:
        return ''
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=5)
        if response.status_code == 200:
            data = response.json()
            cc = data.get('countryCode', '')
            if cc and len(cc) == 2:
                return cc.upper()
    except Exception:
        pass
    return ''

def country_code_to_flag(country_code):
    if not country_code or len(country_code) != 2:
        return ''
    try:
        return chr(0x1F1E6 + ord(country_code[0].upper()) - ord('A')) + \
               chr(0x1F1E6 + ord(country_code[1].upper()) - ord('A'))
    except:
        return ''

def update_server_remarks(servers):
    updated_servers = []
    for idx, server in enumerate(servers, 1):
        base_url = server.split('#')[0]
        remark = server.split('#', 1)[1].strip() if '#' in server else ""
        ip = extract_ip_from_server(server)
        cc = get_country_code(ip)
        flag = country_code_to_flag(cc)
        if "---" in remark:
            _, custom = remark.split("---", 1)
            new_remark = f"Server {idx} {flag}--- {custom.strip()}"
        else:
            new_remark = f"Server {idx} {flag}"
        updated_servers.append(f"{base_url}#{new_remark}")
        time.sleep(0.1)
    return updated_servers

# === Enhanced User Management Functions ===

USER_LIST_FILE = 'user_list.txt'
BLOCKED_SYMBOL = '🚫'
IRAN_TZ = pytz.timezone('Asia/Tehran')

def get_iran_time():
    utc_now = datetime.datetime.now(pytz.UTC)
    return utc_now.astimezone(IRAN_TZ)

def load_user_list():
    if not os.path.exists(USER_LIST_FILE):
        return []
    with open(USER_LIST_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def save_user_list(users):
    with open(USER_LIST_FILE, 'w', encoding='utf-8') as f:
        if users:
            f.write('\n'.join(users) + '\n')

def extract_username_from_line(user_line):
    clean_line = user_line.replace(BLOCKED_SYMBOL, '').strip()
    if '#' in clean_line:
        clean_line = clean_line.split('#')[0].strip()
    if '---' in clean_line:
        before_command = clean_line.split('---')[0].strip()
        username = before_command.split()[0] if before_command.split() else ''
        return username
    else:
        username = clean_line.split()[0] if clean_line.split() else clean_line
        return username

def extract_user_data_from_line(user_line):
    clean_line = user_line.replace(BLOCKED_SYMBOL, '').strip()
    if '---' in clean_line:
        before_command = clean_line.split('---')[0].strip()
        parts = before_command.split()
        if len(parts) > 1:
            return ' '.join(parts[1:])
    else:
        parts = clean_line.split()
        if len(parts) > 1:
            return ' '.join(parts[1:])
    return ''

def extract_notes_from_line(user_line):
    if '#' in user_line:
        return user_line.split('#', 1)[1].strip()
    return ''

def remove_notes_from_line(user_line):
    if '#' in user_line:
        return user_line.split('#')[0].strip()
    return user_line.strip()

def parse_relative_datetime(relative_str):
    if not relative_str:
        return None
    now = get_iran_time()
    today = now.date()
    patterns = [
        r'^(\d{1,2}):(\d{1,2})$',
        r'(\d+)\s*(days?|d)\s+(\d{1,2}):(\d{1,2})',
        r'(\d+)\s*(days?|d)$',
        r'(\d+)\s*(weeks?|w)\s+(\d{1,2}):(\d{1,2})',
        r'(\d+)\s*(weeks?|w)$',
        r'(\d+)\s*(months?|m)\s+(\d{1,2}):(\d{2})',
        r'(\d+)\s*(months?|m)$',
        r'(\d+)\s*(hours?|h)$',
    ]
    for i, pattern in enumerate(patterns):
        match = re.match(pattern, relative_str.strip(), re.IGNORECASE)
        if match:
            groups = match.groups()
            if i == 0:
                hour, minute = int(groups[0]), int(groups[1])
                if 0 <= hour <= 23 and 0 <= minute <= 59:
                    target_time = datetime.time(hour, minute)
                    naive_dt = datetime.datetime.combine(today, target_time)
                    target_datetime = IRAN_TZ.localize(naive_dt)
                    if target_datetime <= now:
                        tomorrow = today + datetime.timedelta(days=1)
                        naive_dt = datetime.datetime.combine(tomorrow, target_time)
                        target_datetime = IRAN_TZ.localize(naive_dt)
                    return target_datetime
                else:
                    return None
            else:
                amount = int(groups[0])
                unit = groups[1].lower() if len(groups) > 1 else ''
                if unit.startswith('d'):
                    delta = datetime.timedelta(days=amount)
                elif unit.startswith('w'):
                    delta = datetime.timedelta(weeks=amount)
                elif unit.startswith('m'):
                    delta = datetime.timedelta(days=amount * 30)
                elif unit.startswith('h'):
                    delta = datetime.timedelta(hours=amount)
                else:
                    continue
                if len(groups) >= 4:
                    hour, minute = int(groups[2]), int(groups[3])
                    if not (0 <= hour <= 23 and 0 <= minute <= 59):
                        continue
                else:
                    hour, minute = 23, 59
                target_date = (now + delta).date()
                target_time = datetime.time(hour, minute)
                naive_dt = datetime.datetime.combine(target_date, target_time)
                target_datetime = IRAN_TZ.localize(naive_dt)
                return target_datetime
    return None

def format_expiry_datetime(target_datetime):
    if not target_datetime:
        return ""
    now = get_iran_time()
    if target_datetime.date() == now.date():
        return f"{target_datetime.strftime('%H:%M')} expires today"
    else:
        return f"{target_datetime.strftime('%Y-%m-%d %H:%M')} expires"

def check_expiry_datetime(user_line):
    now = get_iran_time()
    datetime_patterns = [
        r'(\d{4}-\d{2}-\d{2} \d{1,2}:\d{2}) expires',
        r'(\d{1,2}:\d{2}) expires today'
    ]
    for pattern in datetime_patterns:
        match = re.search(pattern, user_line)
        if match:
            datetime_str = match.group(1)
            try:
                if 'expires today' in user_line:
                    time_part = datetime_str
                    hour, minute = map(int, time_part.split(':'))
                    if not (0 <= hour <= 23 and 0 <= minute <= 59):
                        continue
                    today = now.date()
                    target_time = datetime.time(hour, minute)
                    naive_dt = datetime.datetime.combine(today, target_time)
                    target_datetime = IRAN_TZ.localize(naive_dt)
                else:
                    target_datetime = datetime.datetime.strptime(datetime_str, '%Y-%m-%d %H:%M')
                    target_datetime = IRAN_TZ.localize(target_datetime)
                if target_datetime <= now:
                    return True, target_datetime
            except Exception:
                continue
    return False, None

def add_user_to_list(username, user_data=''):
    users = load_user_list()
    existing_usernames = [extract_username_from_line(user) for user in users]
    if username not in existing_usernames:
        new_entry = f"{username} {user_data}" if user_data else username
        users.insert(0, new_entry)
        save_user_list(users)
        print(f"📝 Added new user: {new_entry}")
        return True
    else:
        print(f"⚠️  User already exists: {username}")
        return False

def create_subscription_file(username):
    subscription_dir = 'subscriptions'
    if not os.path.exists(subscription_dir):
        os.makedirs(subscription_dir)
    sub_file = os.path.join(subscription_dir, f"{username}.txt")
    if not os.path.exists(sub_file):
        with open(sub_file, 'w', encoding='utf-8') as f:
            f.write('')
        print(f"📄 Created subscription file: {username}.txt")
        return True
    else:
        print(f"⚠️  Subscription file already exists: {username}.txt")
        return False

def rename_subscription_file(old_username, new_username):
    subscription_dir = 'subscriptions'
    old_file = os.path.join(subscription_dir, f"{old_username}.txt")
    new_file = os.path.join(subscription_dir, f"{new_username}.txt")
    if os.path.exists(old_file):
        if not os.path.exists(new_file):
            os.rename(old_file, new_file)
            print(f"📄 Renamed subscription file: {old_username}.txt → {new_username}.txt")
        else:
            print(f"⚠️ Cannot rename: {new_username}.txt already exists")
    else:
        print(f"⚠️ Subscription file not found: {old_username}.txt")

def process_user_commands():
    users = load_user_list()
    updated_users = []
    blocked_users = set()
    unblocked_users = set()
    deleted_users = set()
    new_users = set()
    renamed_users = {}
    for user_line in users:
        if '---b' in user_line:
            username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            blocked_users.add(username)
            if user_data and notes:
                updated_line = f"{BLOCKED_SYMBOL}{username} {user_data} #{notes}"
            elif user_data:
                updated_line = f"{BLOCKED_SYMBOL}{username} {user_data}"
            elif notes:
                updated_line = f"{BLOCKED_SYMBOL}{username} #{notes}"
            else:
                updated_line = f"{BLOCKED_SYMBOL}{username}"
            updated_users.append(updated_line)
        elif '---ub' in user_line:
            username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            unblocked_users.add(username)
            if user_data and notes:
                updated_line = f"{username} {user_data} #{notes}"
            elif user_data:
                updated_line = f"{username} {user_data}"
            elif notes:
                updated_line = f"{username} #{notes}"
            else:
                updated_line = username
            updated_users.append(updated_line)
        elif '---d' in user_line:
            username = extract_username_from_line(user_line)
            deleted_users.add(username)
        elif '---m' in user_line:
            username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            new_users.add(username)
            if create_subscription_file(username):
                if user_data and notes:
                    updated_line = f"{username} {user_data} #{notes}"
                elif user_data:
                    updated_line = f"{username} {user_data}"
                elif notes:
                    updated_line = f"{username} #{notes}"
                else:
                    updated_line = username
                updated_users.append(updated_line)
            else:
                if user_data and notes:
                    updated_line = f"{username} {user_data} #{notes}"
                elif user_data:
                    updated_line = f"{username} {user_data}"
                elif notes:
                    updated_line = f"{username} #{notes}"
                else:
                    updated_line = username
                updated_users.append(updated_line)
        elif '---r' in user_line:
            old_username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            command_part = user_line.split('---r')[1]
            if '#' in command_part:
                command_part = command_part.split('#')[0]
            new_username = command_part.strip().split()[0] if command_part.strip() else ''
            if new_username and new_username != old_username:
                renamed_users[old_username] = new_username
                symbol = BLOCKED_SYMBOL if user_line.startswith(BLOCKED_SYMBOL) else ''
                if user_data and notes:
                    updated_line = f"{symbol}{new_username} {user_data} #{notes}"
                elif user_data:
                    updated_line = f"{symbol}{new_username} {user_data}"
                elif notes:
                    updated_line = f"{symbol}{new_username} #{notes}"
                else:
                    updated_line = f"{symbol}{new_username}"
                updated_users.append(updated_line)
                rename_subscription_file(old_username, new_username)
            else:
                updated_users.append(user_line)
        elif '---es' in user_line:
            username = extract_username_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            parts = user_line.split('---es')
            if len(parts) > 1:
                time_part = parts[1]
                if '#' in time_part:
                    time_part = time_part.split('#')[0]
                time_part = time_part.strip()
                user_data_before = parts[0].replace(BLOCKED_SYMBOL, '').strip()
                user_data_parts = user_data_before.split()
                if user_data_parts:
                    user_data_parts.pop(0)
                    existing_data = ' '.join(user_data_parts)
                    if '#' in existing_data:
                        existing_data = existing_data.split('#')[0].strip()
                else:
                    existing_data = ''
                target_datetime = parse_relative_datetime(time_part)
                if target_datetime:
                    formatted_expiry = format_expiry_datetime(target_datetime)
                    symbol = BLOCKED_SYMBOL if user_line.startswith(BLOCKED_SYMBOL) else ''
                    if existing_data and notes:
                        updated_line = f"{symbol}{username} {formatted_expiry} {existing_data} #{notes}"
                    elif existing_data:
                        updated_line = f"{symbol}{username} {formatted_expiry} {existing_data}"
                    elif notes:
                        updated_line = f"{symbol}{username} {formatted_expiry} #{notes}"
                    else:
                        updated_line = f"{symbol}{username} {formatted_expiry}"
                    updated_users.append(updated_line)
                else:
                    updated_users.append(user_line)
            else:
                updated_users.append(user_line)
        else:
            updated_users.append(user_line)
    save_user_list(updated_users)
    for old_name, new_name in renamed_users.items():
        existing_blocked = get_blocked_users()
        if old_name in existing_blocked:
            existing_blocked.remove(old_name)
            existing_blocked.add(new_name)
            with open('blocked_users.txt', 'w', encoding='utf-8') as f:
                for user in existing_blocked:
                    f.write(f"{user}\n")
    existing_blocked = get_blocked_users()
    if blocked_users:
        all_blocked = existing_blocked.union(blocked_users)
    else:
        all_blocked = existing_blocked
    if unblocked_users:
        all_blocked = all_blocked - unblocked_users
    if deleted_users:
        all_blocked = all_blocked - deleted_users
    with open('blocked_users.txt', 'w', encoding='utf-8') as f:
        for user in all_blocked:
            f.write(f"{user}\n")
    subscription_dir = 'subscriptions'
    for username in deleted_users:
        sub_file = os.path.join(subscription_dir, f"{username}.txt")
        if os.path.exists(sub_file):
            os.remove(sub_file)

def check_expired_users():
    users = load_user_list()
    updated_users = []
    expired_users = []
    for user_line in users:
        username = extract_username_from_line(user_line)
        is_expired, expiry_time = check_expiry_datetime(user_line)
        if is_expired and not user_line.startswith(BLOCKED_SYMBOL):
            expired_users.append(username)
            updated_line = f"{BLOCKED_SYMBOL}{user_line}"
            updated_users.append(updated_line)
        else:
            updated_users.append(user_line)
    if expired_users:
        save_user_list(updated_users)
        existing_blocked = get_blocked_users()
        all_blocked = existing_blocked.union(set(expired_users))
        with open('blocked_users.txt', 'w', encoding='utf-8') as f:
            for user in all_blocked:
                f.write(f"{user}\n")

def discover_new_subscriptions():
    subscription_dir = 'subscriptions'
    if not os.path.exists(subscription_dir):
        return
    subscription_files = [f for f in os.listdir(subscription_dir) if f.endswith('.txt')]
    existing_users = load_user_list()
    existing_usernames = [extract_username_from_line(user) for user in existing_users]
    for filename in subscription_files:
        username = filename[:-4]
        if username not in existing_usernames:
            add_user_to_list(username)

def normalize_vmess_url(server_line):
    try:
        base64_part = server_line[8:].split('#')[0]
        decoded = base64.b64decode(base64_part).decode('utf-8')
        config = json.loads(decoded)
        standard_keys = ['v', 'ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'host', 'path', 'tls']
        normalized_config = {}
        for key in standard_keys:
            val = config.get(key, '')
            if key in ['port', 'aid'] and val != '':
                val = str(val)
            if val is None:
                val = ''
            normalized_config[key] = val
        sorted_config = {k: normalized_config[k] for k in sorted(normalized_config)}
        normalized_json = json.dumps(sorted_config, separators=(',', ':'))
        normalized_base64 = base64.b64encode(normalized_json.encode('utf-8')).decode('utf-8')
        return f"vmess://{normalized_base64}"
    except Exception:
        return server_line

def extract_server_config(server_line):
    try:
        server_line = server_line.strip()
        if server_line.startswith('vmess://'):
            return normalize_vmess_url(server_line)
        elif server_line.startswith(('vless://', 'trojan://', 'ss://')):
            url_part = server_line.split('#')[0]
            parsed = urlparse(url_part)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path
            query_params = parse_qsl(parsed.query, keep_blank_values=True)
            query_params.sort()
            query = urlencode(query_params, doseq=True)
            normalized = urlunparse((scheme, netloc, path, '', query, ''))
            return normalized
        else:
            return server_line.split('#')[0].strip().lower()
    except Exception:
        return server_line

# === LOG HISTORY FUNCTION ===

NON_WORKING_FILE = 'non_working.txt'
MAIN_FILE = 'servers.txt'
HISTORY_FILE = 'server_history.txt'
QUARANTINE_DAYS = 3

def log_history(server, action, max_entries=1000):
    iran_time = get_iran_time()
    now = iran_time.strftime("%Y-%m-%d %H:%M")
    new_entry = f"{server} | {action} | {now}\n"
    existing_lines = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            existing_lines = f.readlines()
    if len(existing_lines) >= max_entries:
        existing_lines = existing_lines[:max_entries-1]
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        f.write(new_entry)
        f.writelines(existing_lines)

# === REMOVE DUPLICATES WITH LOGGING ===

def remove_duplicates(servers):
    seen_configs = {}
    unique_servers = []
    for server in servers:
        if not server.strip():
            continue
        config_key = extract_server_config(server)
        if config_key in seen_configs:
            # Log duplicate removal
            log_history(server, "removed_duplicate")
            continue
        else:
            seen_configs[config_key] = server.strip()
            unique_servers.append(server.strip())
    return unique_servers

def parse_non_working_line(line):
    try:
        server, date_str = line.rsplit('|', 1)
        server = server.strip()
        date_str = date_str.strip()
        dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M")
        return server, dt
    except Exception:
        return None, None

def load_main_servers():
    if not os.path.exists(MAIN_FILE):
        return []
    with open(MAIN_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def save_main_servers(servers):
    with open(MAIN_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(servers) + '\n')

def load_non_working():
    if not os.path.exists(NON_WORKING_FILE):
        return []
    with open(NON_WORKING_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def save_non_working(servers):
    with open(NON_WORKING_FILE, 'w', encoding='utf-8') as f:
        if servers:
            f.write('\n'.join(servers) + '\n')
        else:
            f.truncate(0)

def cleanup_non_working():
    today = get_iran_time()
    non_working_lines = load_non_working()
    keep_non_working = []
    for line in non_working_lines:
        server, dt = parse_non_working_line(line)
        if not server or not dt:
            continue
        days_in_quarantine = (today.replace(tzinfo=None) - dt).days
        if days_in_quarantine >= QUARANTINE_DAYS:
            log_history(server, "removed_after_3_days")
        else:
            keep_non_working.append(line)
    save_non_working(keep_non_working)

def move_server_to_non_working(server_line):
    iran_time = get_iran_time()
    now_str = iran_time.strftime("%Y-%m-%d %H:%M")
    entry = f"{server_line} | {now_str}"
    non_working = load_non_working()
    if not any(server_line in line for line in non_working):
        non_working.append(entry)
        save_non_working(non_working)
        log_history(server_line, "moved_to_non_working")

def move_server_to_main(server_line):
    main_servers = load_main_servers()
    normalized_new = extract_server_config(server_line)
    for existing in main_servers:
        if extract_server_config(existing) == normalized_new:
            return
    main_servers.append(server_line)
    save_main_servers(main_servers)
    log_history(server_line, "moved_to_main")

def process_non_working_recovery():
    non_working_lines = load_non_working()
    keep_non_working = []
    for line in non_working_lines:
        server, dt = parse_non_working_line(line)
        if not server or not dt:
            continue
        if validate_server(server):
            move_server_to_main(server)
            log_history(server, "recovered_to_main")
        else:
            keep_non_working.append(line)
    save_non_working(keep_non_working)

def is_fake_server(server_line):
    fake_indicators = [
        "127.0.0.1",
        "localhost",
        "fake",
        "Fake Server",
        "fakepas",
        "12345678-1234-1234-1234-123456789",
        "YWVzLTI1Ni1nY206ZmFrZXBhc3N3b3Jk"
    ]
    server_lower = server_line.lower()
    for indicator in fake_indicators:
        if indicator.lower() in server_lower:
            return True
    return False

def validate_server(server_line):
    try:
        hostname = None
        port = None
        if server_line.startswith('vless://'):
            url_part = server_line.split('#')[0]
            parsed = urlparse(url_part)
            hostname = parsed.hostname
            port = parsed.port or 443
        elif server_line.startswith('vmess://'):
            config_data = base64.b64decode(server_line[8:]).decode('utf-8')
            config = json.loads(config_data)
            hostname = config.get('add')
            port = int(config.get('port', 443))
        elif server_line.startswith('ss://'):
            url_part = server_line.split('#')[0]
            parsed = urlparse(url_part)
            hostname = parsed.hostname
            port = parsed.port or 8388
        elif server_line.startswith('trojan://'):
            url_part = server_line.split('#')[0]
            parsed = urlparse(url_part)
            hostname = parsed.hostname
            port = parsed.port or 443
        if hostname and port:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((hostname, port))
            sock.close()
            return result == 0
    except Exception:
        return False
    return False

def get_blocked_users():
    blocked_users = set()
    try:
        with open('blocked_users.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    blocked_users.add(line)
    except FileNotFoundError:
        pass
    return blocked_users

def should_block_user(username, blocked_users):
    return username in blocked_users

def get_fake_servers():
    fake_remark = "اشتراک شما تمام شده است لطفا اشتراک خود را تمدید کنید"
    return [
        f"vless://12345678-1234-1234-1234-123456789abc@127.0.0.1:443?encryption=none&security=tls&type=ws&path=%2F#{fake_remark}"
    ]

def distribute_servers(servers, username):
    return servers

def update_all_subscriptions():
    process_user_commands()
    check_expired_users()
    discover_new_subscriptions()
    cleanup_non_working()
    process_non_working_recovery()
    # --- NEW: Validate main server list and quarantine non-working entries ---
    current_servers = load_main_servers()
    valid_servers = []
    for srv in current_servers:
        # Detect obviously fake servers first
        if is_fake_server(srv):
            move_server_to_non_working(srv)
            continue
        # Actively check if the server is reachable
        if not validate_server(srv):
            move_server_to_non_working(srv)
            continue
        valid_servers.append(srv)
    # Persist the cleaned list so that subsequent steps work with only healthy servers
    save_main_servers(valid_servers)

    # Continue the pipeline using the verified server list
    all_servers = update_server_remarks(valid_servers)
    unique_servers = remove_duplicates(all_servers)
    save_main_servers(unique_servers)
    blocked_users = get_blocked_users()
    subscription_dir = 'subscriptions'
    if not os.path.exists(subscription_dir):
        os.makedirs(subscription_dir)
    subscription_files = [f for f in os.listdir(subscription_dir) if f.endswith('.txt')]
    for filename in subscription_files:
        username = filename[:-4]
        if should_block_user(username, blocked_users):
            servers_for_user = get_fake_servers()
        else:
            servers_for_user = unique_servers
        subscription_path = os.path.join(subscription_dir, filename)
        with open(subscription_path, 'w', encoding='utf-8') as f:
            subscription_content = '\n'.join(servers_for_user)
            encoded_content = base64.b64encode(subscription_content.encode('utf-8')).decode('utf-8')
            f.write(encoded_content)

if __name__ == "__main__":
    update_all_subscriptions()
