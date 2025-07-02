import os
import base64
import random
import json
import datetime
from urllib.parse import urlparse

# === Existing Functions ===

def extract_server_config(server_line):
    try:
        server_line = server_line.strip()
        if server_line.startswith('vmess://'):
            config_data = base64.b64decode(server_line[8:]).decode('utf-8')
            config = json.loads(config_data)
            key = f"vmess://{config.get('add')}:{config.get('port')}:{config.get('id')}:{config.get('net')}:{config.get('type')}"
            return key
        elif server_line.startswith('vless://'):
            url_part = server_line.split('#')[0]
            parsed = urlparse(url_part)
            key = f"vless://{parsed.hostname}:{parsed.port}:{parsed.username}:{parsed.path}"
            return key
        elif server_line.startswith('ss://'):
            url_part = server_line.split('#')[0]
            parsed = urlparse(url_part)
            key = f"ss://{parsed.hostname}:{parsed.port}:{parsed.username}"
            return key
        elif server_line.startswith('trojan://'):
            url_part = server_line.split('#')[0]
            parsed = urlparse(url_part)
            key = f"trojan://{parsed.hostname}:{parsed.port}:{parsed.username}"
            return key
        else:
            return server_line.split('#')[0].strip()
    except Exception as e:
        print(f"Error parsing server config: {e}")
        return server_line

def remove_duplicates(servers):
    seen_configs = {}
    unique_servers = []
    for server in servers:
        if not server.strip():
            continue
        config_key = extract_server_config(server)
        if config_key not in seen_configs:
            seen_configs[config_key] = server.strip()
            unique_servers.append(server.strip())
        else:
            print(f"Duplicate removed: {server.strip()}")
    return unique_servers

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
    return [
        "vmess://eyJ2IjoiMiIsInBzIjoiRmFrZSBTZXJ2ZXIgMSIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOiI4MCIsInR5cGUiOiJub25lIiwiaWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODkwYWIiLCJhaWQiOiIwIiwibmV0Ijoid3MiLCJwYXRoIjoiLyIsImhvc3QiOiIiLCJ0bHMiOiIifQ==",
        "vless://12345678-1234-1234-1234-123456789abc@127.0.0.1:443?encryption=none&security=tls&type=ws&path=%2F#Fake%20Server%202",
        "ss://YWVzLTI1Ni1nY206ZmFrZXBhc3N3b3Jk@127.0.0.1:8388#Fake%20Server%203"
    ]

def distribute_servers(servers, username):
    if not servers:
        return get_fake_servers()
    return servers

# === Quarantine (non_working.txt) Functions ===

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
            print(f"Removing from non_working.txt (over {QUARANTINE_DAYS} days): {server}")
            log_history(server, "removed_after_3_days")
            changed = True
        else:
            keep_non_working.append(line)
    save_non_working(keep_non_working)
    if changed:
        print("non_working.txt cleaned up.")

def move_server_to_non_working(server_line):
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    entry = f"{server_line} | {now_str}"
    non_working = load_non_working()
    if not any(server_line in line for line in non_working):
        non_working.append(entry)
        save_non_working(non_working)
        log_history(server_line, "moved_to_non_working")
        print(f"Moved to non_working.txt: {server_line}")

def move_server_to_main(server_line):
    main_servers = load_main_servers()
    server_no_remark = server_line.split('#')[0].strip()
    if not any(server_no_remark in s for s in main_servers):
        main_servers.append(server_line)
        save_main_servers(main_servers)
        log_history(server_line, "moved_to_main")
        print(f"Moved to main.txt: {server_line}")

def process_non_working_recovery(server_validator):
    non_working_lines = load_non_working()
    keep_non_working = []
    changed = False

    for line in non_working_lines:
        server, dt = parse_non_working_line(line)
        if not server or not dt:
            continue
        if server_validator(server):
            print(f"Recovered: {server}")
            move_server_to_main(server)
            log_history(server, "recovered_to_main")
            changed = True
        else:
            keep_non_working.append(line)
    save_non_working(keep_non_working)
    if changed:
        print("non_working.txt updated after recovery.")

# === Main Update Function ===

def update_all_subscriptions():
    # Step 1: Clean up non_working.txt (remove servers over 3 days)
    cleanup_non_working()

    # Step 2: Read servers from main.txt
    try:
        with open('main.txt', 'r', encoding='utf-8') as f:
            all_servers = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print("❌ main.txt not found")
        return

    print(f"📖 Read {len(all_servers)} servers from main.txt")

    # Step 3: Remove duplicates
    unique_servers = remove_duplicates(all_servers)

    # Step 4: Update main.txt if duplicates were removed
    if len(unique_servers) < len(all_servers):
        print(f"💾 Updating main.txt: {len(all_servers)} → {len(unique_servers)} servers")
        with open('main.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_servers) + '\n')

    # Step 5: Get blocked users
    blocked_users = get_blocked_users()

    # Step 6: Process subscription files
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

# To use quarantine logic:
# - When you detect a server is offline, call move_server_to_non_working(server_line)
# - To try to recover servers, call process_non_working_recovery(your_validator_function)
