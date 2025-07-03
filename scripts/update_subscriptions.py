import os
import base64
import json
import datetime
import socket
import urllib.parse
from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode
import re
import requests
import time

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

def get_next_server_number(existing_numbers):
    n = 1
    while n in existing_numbers:
        n += 1
    return n

def parse_remark(remark):
    """Returns (base, flag, custom)"""
    if "---" in remark:
        base, custom = remark.split("---", 1)
        base = base.strip()
        custom = custom.strip()
    else:
        base = remark.strip()
        custom = ""
    # Extract flag if present
    m = re.match(r"^(.*?)(\s*[\U0001F1E6-\U0001F1FF]{2})$", base)
    if m:
        base = m.group(1).strip()
        flag = m.group(2).strip()
    else:
        flag = ""
    return base, flag, custom

def update_server_remarks(servers):
    existing_numbers = set()
    updated_servers = []
    for server in servers:
        if '#' in server:
            remark = server.split('#', 1)[1].strip()
        else:
            remark = ""

        # Custom remark requested (--- present)
        if "---" in remark:
            base, flag, custom = parse_remark(remark)
            m = re.match(r"Server (\d+)", base)
            if m:
                num = int(m.group(1))
                existing_numbers.add(num)
            else:
                num = get_next_server_number(existing_numbers)
                existing_numbers.add(num)
                base = f"Server {num}"
            ip = extract_ip_from_server(server)
            cc = get_country_code(ip)
            flag = country_code_to_flag(cc)
            new_remark = f"{base} {flag}--- {custom}".strip()
            updated_servers.append(f"{server.split('#')[0]}#{new_remark}")
            continue

        m = re.match(r"Server (\d+)", remark)
        if m:
            num = int(m.group(1))
            existing_numbers.add(num)
            ip = extract_ip_from_server(server)
            cc = get_country_code(ip)
            flag = country_code_to_flag(cc)
            new_remark = f"Server {num} {flag}".strip()
            updated_servers.append(f"{server.split('#')[0]}#{new_remark}")
        else:
            if remark:
                ip = extract_ip_from_server(server)
                cc = get_country_code(ip)
                flag = country_code_to_flag(cc)
                new_remark = f"{remark} {flag}--- ThisIsCustom"
                updated_servers.append(f"{server.split('#')[0]}#{new_remark}")
            else:
                num = get_next_server_number(existing_numbers)
                existing_numbers.add(num)
                ip = extract_ip_from_server(server)
                cc = get_country_code(ip)
                flag = country_code_to_flag(cc)
                new_remark = f"Server {num} {flag}".strip()
                updated_servers.append(f"{server.split('#')[0]}#{new_remark}")
        time.sleep(0.1)  # Avoid API rate limit
    return updated_servers

# === Duplicate Detection ===

def extract_server_config(server_line):
    try:
        server_line = server_line.strip()
        if server_line.startswith('vmess://'):
            base64_part = server_line[8:].split('#')[0]
            decoded = base64.b64decode(base64_part).decode('utf-8')
            config = json.loads(decoded)
            keys = ['v', 'ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'host', 'path', 'tls']
            norm = {k: str(config.get(k, '')) for k in keys}
            norm_str = json.dumps(norm, sort_keys=True)
            return norm_str
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

def remove_duplicates(servers):
    seen_configs = {}
    unique_servers = []
    for server in servers:
        if not server.strip():
            continue
        config_key = extract_server_config(server)
        if config_key in seen_configs:
            continue
        else:
            seen_configs[config_key] = server.strip()
            unique_servers.append(server.strip())
    return unique_servers

# === Quarantine and Non-working ===

NON_WORKING_FILE = 'non_working.txt'
MAIN_FILE = 'main.txt'
HISTORY_FILE = 'server_history.txt'
QUARANTINE_DAYS = 3

def parse_non_working_line(line):
    try:
        server, date_str = line.rsplit('|', 1)
        server = server.strip()
        date_str = date_str.strip()
        dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M")
        return server, dt
    except Exception as e:
        print(f"Parse error: {e} in line: {line}")
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

def log_history(server, action):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(HISTORY_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{server} | {action} | {now}\n")

def cleanup_non_working():
    today = datetime.datetime.now()
    non_working_lines = load_non_working()
    keep_non_working = []
    changed = False

    for line in non_working_lines:
        server, dt = parse_non_working_line(line)
        if not server or not dt:
            continue
        days_in_quarantine = (today - dt).days
        if days_in_quarantine >= QUARANTINE_DAYS:
            print(f"🗑️  Removing from non_working.txt (over {QUARANTINE_DAYS} days): {server}")
            log_history(server, "removed_after_3_days")
            changed = True
        else:
            keep_non_working.append(line)
    
    save_non_working(keep_non_working)
    if changed:
        print("🧹 non_working.txt cleaned up.")

def move_server_to_non_working(server_line):
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    entry = f"{server_line} | {now_str}"
    non_working = load_non_working()
    if not any(server_line in line for line in non_working):
        non_working.append(entry)
        save_non_working(non_working)
        log_history(server_line, "moved_to_non_working")
        print(f"🚫 Moved to non_working.txt: {server_line}")

def move_server_to_main(server_line):
    main_servers = load_main_servers()
    normalized_new = extract_server_config(server_line)
    for existing in main_servers:
        if extract_server_config(existing) == normalized_new:
            print(f"⚠️  Server already exists in main.txt: {server_line}")
            return
    main_servers.append(server_line)
    save_main_servers(main_servers)
    log_history(server_line, "moved_to_main")
    print(f"✅ Moved to main.txt: {server_line}")

def process_non_working_recovery():
    non_working_lines = load_non_working()
    keep_non_working = []
    changed = False

    for line in non_working_lines:
        server, dt = parse_non_working_line(line)
        if not server or not dt:
            continue
        if validate_server(server):
            print(f"🔄 Recovered: {server}")
            move_server_to_main(server)
            log_history(server, "recovered_to_main")
            changed = True
        else:
            keep_non_working.append(line)
    save_non_working(keep_non_working)
    if changed:
        print("🔄 non_working.txt updated after recovery.")

# === Validation and Fake Server Detection ===

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
            parsed = urllib.parse.urlparse(url_part)
            hostname = parsed.hostname
            port = parsed.port or 443
        elif server_line.startswith('vmess://'):
            config_data = base64.b64decode(server_line[8:]).decode('utf-8')
            config = json.loads(config_data)
            hostname = config.get('add')
            port = int(config.get('port', 443))
        elif server_line.startswith('ss://'):
            url_part = server_line.split('#')[0]
            parsed = urllib.parse.urlparse(url_part)
            hostname = parsed.hostname
            port = parsed.port or 8388
        elif server_line.startswith('trojan://'):
            url_part = server_line.split('#')[0]
            parsed = urllib.parse.urlparse(url_part)
            hostname = parsed.hostname
            port = parsed.port or 443
        if hostname and port:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((hostname, port))
            sock.close()
            if result == 0:
                print(f"✅ Server reachable: {hostname}:{port}")
                return True
            else:
                print(f"❌ Server unreachable: {hostname}:{port}")
                return False
    except Exception as e:
        print(f"❌ Validation error for {server_line[:50]}...: {e}")
        return False
    return False

# === User Blocking and Subscription Generation ===

def get_blocked_users():
    blocked_users = set()
    try:
        with open('blocked_users.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    blocked_users.add(line)
        print(f"📋 Loaded {len(blocked_users)} blocked users")
    except FileNotFoundError:
        print("ℹ️  No blocked_users.txt found - no users blocked")
    return blocked_users

def should_block_user(username, blocked_users):
    return username in blocked_users

def get_fake_servers():
    return [
        "vmess://eyJ2IjoiMiIsInBzIjoiRmFrZSBTZXJ2ZXIgMSIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOiI4MCIsInR5cGUiOiJub25lIiwiaWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODkwYWIiLCJhaWQiOiIwIiwibmV0Ijoid3MiLCJwYXRoIjoiLyIsImhvc3QiOiIiLCJ0bHMiOiIifQ==",
        "vless://12345678-1234-1234-1234-123456789abc@127.0.0.1:443?encryption=none&security=tls&type=ws&path=%2F#Fake%20Server%202",
        "ss://YWVzLTI1Ni1nY206ZmFrZXBhc3N3b3Jk@127.0.0.1:8388#Fake%20Server%203"
    ]

def distribute_servers(servers, username):
    if not servers:
        return get_fake_servers()
    return servers

# === Main Update Function ===

def update_all_subscriptions():
    cleanup_non_working()
    process_non_working_recovery()
    all_servers = load_main_servers()
    all_servers = update_server_remarks(all_servers)
    unique_servers = remove_duplicates(all_servers)
    save_main_servers(unique_servers)
    blocked_users = get_blocked_users()
    subscription_dir = 'subscriptions'
    if not os.path.exists(subscription_dir):
        os.makedirs(subscription_dir)
        print(f"📁 Created {subscription_dir} directory")
    subscription_files = [f for f in os.listdir(subscription_dir) if f.endswith('.txt')]
    if not subscription_files:
        print("⚠️  No subscription files found in subscriptions/ directory")
        return
    print(f"🔄 Processing {len(subscription_files)} subscription files...")
    for filename in subscription_files:
        username = filename[:-4]
        if should_block_user(username, blocked_users):
            servers_for_user = get_fake_servers()
            print(f"🚫 {filename}: Blocked user - using {len(servers_for_user)} fake servers")
        else:
            servers_for_user = distribute_servers(unique_servers, username)
            print(f"✅ {filename}: Active user - {len(servers_for_user)} real servers")
        subscription_path = os.path.join(subscription_dir, filename)
        with open(subscription_path, 'w', encoding='utf-8') as f:
            subscription_content = '\n'.join(servers_for_user)
            encoded_content = base64.b64encode(subscription_content.encode('utf-8')).decode('utf-8')
            f.write(encoded_content)
    print("🎉 All subscription files updated successfully!")

if __name__ == "__main__":
    print("🚀 Starting V2Ray subscription update...")
    update_all_subscriptions()
    print("✨ Update process completed!")
