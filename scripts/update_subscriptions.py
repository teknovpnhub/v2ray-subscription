import os
import base64
import json
import datetime
import socket
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

def update_server_remarks(servers):
    updated_servers = []
    for idx, server in enumerate(servers, 1):
        base_url = server.split('#')[0]
        remark = server.split('#', 1)[1].strip() if '#' in server else ""
        ip = extract_ip_from_server(server)
        cc = get_country_code(ip)
        flag = country_code_to_flag(cc)

        # If user adds --- (custom), keep number and flag, add custom text
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

def load_user_list():
    if not os.path.exists(USER_LIST_FILE):
        return []
    with open(USER_LIST_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def save_user_list(users):
    with open(USER_LIST_FILE, 'w', encoding='utf-8') as f:
        if users:
            f.write('\n'.join(users) + '\n')

def add_user_to_list(username):
    """Add new user to top of user_list.txt (username only)"""
    users = load_user_list()
    
    # Extract just usernames from existing entries
    clean_users = []
    for user in users:
        clean_username = extract_username_from_line(user)
        if clean_username:
            clean_users.append(user)  # Keep original format with symbols
    
    # Check if user already exists
    existing_usernames = [extract_username_from_line(user) for user in clean_users]
    if username not in existing_usernames:
        # Add new user at the top
        clean_users.insert(0, username)
        save_user_list(clean_users)
        print(f"📝 Added new user: {username}")

def extract_username_from_line(user_line):
    """Extract clean username from user line (removes symbols and commands)"""
    # Remove blocked symbol
    clean_line = user_line.replace(BLOCKED_SYMBOL, '').strip()
    # Remove commands
    clean_line = re.sub(r'\s*---[a-z]+', '', clean_line).strip()
    return clean_line

def create_subscription_file(username):
    """Create a new subscription file for the user"""
    subscription_dir = 'subscriptions'
    if not os.path.exists(subscription_dir):
        os.makedirs(subscription_dir)
    
    sub_file = os.path.join(subscription_dir, f"{username}.txt")
    if not os.path.exists(sub_file):
        # Create empty subscription file (will be populated by main script)
        with open(sub_file, 'w', encoding='utf-8') as f:
            f.write('')  # Empty file, will be filled by update_all_subscriptions
        print(f"📄 Created subscription file: {username}.txt")
        return True
    else:
        print(f"⚠️  Subscription file already exists: {username}.txt")
        return False

def process_user_commands():
    """Process user commands: ---b (block), ---ub (unblock), ---d (delete), ---m (make new)"""
    users = load_user_list()
    updated_users = []
    blocked_users = set()
    unblocked_users = set()
    deleted_users = set()
    new_users = set()
    
    for user_line in users:
        if '---b' in user_line:
            # Block command
            username = extract_username_from_line(user_line)
            blocked_users.add(username)
            # Add blocked symbol and remove command
            updated_line = f"{BLOCKED_SYMBOL}{username}"
            updated_users.append(updated_line)
            print(f"🚫 Blocked user: {username}")
            
        elif '---ub' in user_line:
            # Unblock command
            username = extract_username_from_line(user_line)
            unblocked_users.add(username)
            # Remove blocked symbol and command
            updated_line = username
            updated_users.append(updated_line)
            print(f"✅ Unblocked user: {username}")
            
        elif '---d' in user_line:
            # Delete command
            username = extract_username_from_line(user_line)
            deleted_users.add(username)
            print(f"🗑️ Deleted user: {username}")
            # Don't add deleted users back to the list
            
        elif '---m' in user_line:
            # Make new subscription command
            username = extract_username_from_line(user_line)
            new_users.add(username)
            if create_subscription_file(username):
                updated_users.append(username)
                print(f"📄 Created new subscription: {username}")
            else:
                # User already exists, just add to list without symbol
                updated_users.append(username)
            
        else:
            # Regular user line (no command)
            updated_users.append(user_line)
    
    save_user_list(updated_users)
    
    # Update blocked_users.txt
    existing_blocked = get_blocked_users()
    
    # Add newly blocked users
    if blocked_users:
        all_blocked = existing_blocked.union(blocked_users)
    else:
        all_blocked = existing_blocked
    
    # Remove unblocked users
    if unblocked_users:
        all_blocked = all_blocked - unblocked_users
    
    # Save updated blocked users list
    with open('blocked_users.txt', 'w', encoding='utf-8') as f:
        for user in all_blocked:
            f.write(f"{user}\n")
    
    # Delete subscription files for deleted users
    subscription_dir = 'subscriptions'
    for username in deleted_users:
        sub_file = os.path.join(subscription_dir, f"{username}.txt")
        if os.path.exists(sub_file):
            os.remove(sub_file)
            print(f"🗑️ Deleted subscription file: {username}.txt")

def discover_new_subscriptions():
    """Discover new subscription files and add to user list"""
    subscription_dir = 'subscriptions'
    if not os.path.exists(subscription_dir):
        return
    
    subscription_files = [f for f in os.listdir(subscription_dir) if f.endswith('.txt')]
    existing_users = load_user_list()
    
    # Extract existing usernames (clean, without symbols)
    existing_usernames = [extract_username_from_line(user) for user in existing_users]
    
    for filename in subscription_files:
        username = filename[:-4]  # Remove .txt extension
        if username not in existing_usernames:
            add_user_to_list(username)

# === Duplicate Detection ===

def normalize_vmess_url(server_line):
    """Normalize VMess URL by sorting JSON keys and standardizing values"""
    try:
        base64_part = server_line[8:].split('#')[0]
        decoded = base64.b64decode(base64_part).decode('utf-8')
        config = json.loads(decoded)
        
        # Standard VMess keys with default values
        standard_keys = ['v', 'ps', 'add', 'port', 'id', 'aid', 'net', 'type', 'host', 'path', 'tls']
        normalized_config = {}
        
        for key in standard_keys:
            val = config.get(key, '')
            # Normalize port and aid to strings
            if key in ['port', 'aid'] and val != '':
                val = str(val)
            # Normalize empty strings
            if val is None:
                val = ''
            normalized_config[key] = val
        
        # Sort keys and create normalized JSON
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

def log_history(server, action, max_entries=1000):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    new_entry = f"{server} | {action} | {now}\n"
    
    # Read existing history
    existing_lines = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            existing_lines = f.readlines()
    
    # Keep only the most recent entries (excluding the new one)
    if len(existing_lines) >= max_entries:
        existing_lines = existing_lines[:max_entries-1]
    
    # Write new entry first, then existing entries
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        f.write(new_entry)
        f.writelines(existing_lines)

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
    fake_remark = "اشتراک شما تمام شده است لطفا اشتراک خود را تمدید کنید"
    return [
        f"vless://12345678-1234-1234-1234-123456789abc@127.0.0.1:443?encryption=none&security=tls&type=ws&path=%2F#{fake_remark}"
    ]

def distribute_servers(servers, username):
    # Always return the latest main.txt content for all users except blocked
    return servers

# === Main Update Function ===

def update_all_subscriptions():
    # Process user commands first
    process_user_commands()
    
    # Discover new subscription files
    discover_new_subscriptions()
    
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
            servers_for_user = unique_servers  # Always use the latest main.txt content!
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
