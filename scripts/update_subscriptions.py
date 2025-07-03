import os
import base64
import random
import json
import datetime
import socket
import urllib.parse
from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode
import re
import requests

# === New Server Remark and Flag Functions ===

def extract_ip_from_server(server_line):
    """Extract IP address from server line"""
    try:
        # For VLESS, VMess, SS, Trojan
        if server_line.startswith('vless://') or server_line.startswith('trojan://'):
            url_part = server_line.split('#')[0]
            parsed = urlparse(url_part)
            return parsed.hostname
        elif server_line.startswith('vmess://'):
            base64_part = server_line[8:].split('#')[0]
            decoded = base64.b64decode(base64_part).decode('utf-8')
            config = json.loads(decoded)
            return config.get('add')
        elif server_line.startswith('ss://'):
            url_part = server_line.split('#')[0]
            parsed = urlparse(url_part)
            return parsed.hostname
        # Add more protocols as needed
        return None
    except Exception as e:
        print(f"Error extracting IP: {e}")
        return None

def get_country_code(ip):
    """Get country code from IP using free API"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('countryCode', '')
    except Exception as e:
        print(f"Error getting country for {ip}: {e}")
    return ''

def country_code_to_flag(country_code):
    """Convert country code to flag emoji"""
    if not country_code or len(country_code) != 2:
        return ''
    return chr(0x1F1E6 + ord(country_code[0].upper()) - ord('A')) + \
           chr(0x1F1E6 + ord(country_code[1].upper()) - ord('A'))

def get_next_server_number(existing_remarks):
    """Find the next available server number"""
    numbers = set()
    for remark in existing_remarks:
        match = re.match(r"Server (\d+)", remark, re.IGNORECASE)
        if match:
            numbers.add(int(match.group(1)))
    
    n = 1
    while n in numbers:
        n += 1
    return n

def has_custom_remark(server_line):
    """Check if server has a custom remark (not auto-generated)"""
    if '#' not in server_line:
        return False
    
    remark = server_line.split('#', 1)[1].strip()
    # If remark starts with "Server" followed by number and optional flag, it's auto-generated
    if re.match(r"Server \d+(\s+🇦🇿|🇦🇩|🇦🇪|🇦🇫|🇦🇬|🇦🇮|🇦🇱|🇦🇲|🇦🇴|🇦🇶|🇦🇷|🇦🇸|🇦🇹|🇦🇺|🇦🇼|🇦🇽|🇦🇿|🇧🇦|🇧🇧|🇧🇩|🇧🇪|🇧🇫|🇧🇬|🇧🇭|🇧🇮|🇧🇯|🇧🇱|🇧🇲|🇧🇳|🇧🇴|🇧🇶|🇧🇷|🇧🇸|🇧🇹|🇧🇻|🇧🇼|🇧🇾|🇧🇿|🇨🇦|🇨🇨|🇨🇩|🇨🇫|🇨🇬|🇨🇭|🇨🇮|🇨🇰|🇨🇱|🇨🇲|🇨🇳|🇨🇴|🇨🇵|🇨🇷|🇨🇺|🇨🇻|🇨🇼|🇨🇽|🇨🇾|🇨🇿|🇩🇪|🇩🇬|🇩🇯|🇩🇰|🇩🇲|🇩🇴|🇩🇿|🇪🇦|🇪🇨|🇪🇪|🇪🇬|🇪🇭|🇪🇷|🇪🇸|🇪🇹|🇪🇺|🇫🇮|🇫🇯|🇫🇰|🇫🇲|🇫🇴|🇫🇷|🇬🇦|🇬🇧|🇬🇩|🇬🇪|🇬🇫|🇬🇬|🇬🇭|🇬🇮|🇬🇱|🇬🇲|🇬🇳|🇬🇵|🇬🇶|🇬🇷|🇬🇸|🇬🇹|🇬🇺|🇬🇼|🇬🇾|🇭🇰|🇭🇲|🇭🇳|🇭🇷|🇭🇹|🇭🇺|🇮🇨|🇮🇩|🇮🇪|🇮🇱|🇮🇲|🇮🇳|🇮🇴|🇮🇶|🇮🇷|🇮🇸|🇮🇹|🇯🇪|🇯🇲|🇯🇴|🇯🇵|🇰🇪|🇰🇬|🇰🇭|🇰🇮|🇰🇲|🇰🇳|🇰🇵|🇰🇷|🇰🇼|🇰🇾|🇰🇿|🇱🇦|🇱🇧|🇱🇨|🇱🇮|🇱🇰|🇱🇷|🇱🇸|🇱🇹|🇱🇺|🇱🇻|🇱🇾|🇲🇦|🇲🇨|🇲🇩|🇲🇪|🇲🇫|🇲🇬|🇲🇭|🇲🇰|🇲🇱|🇲🇲|🇲🇳|🇲🇴|🇲🇵|🇲🇶|🇲🇷|🇲🇸|🇲🇹|🇲🇺|🇲🇻|🇲🇼|🇲🇽|🇲🇾|🇲🇿|🇳🇦|🇳🇨|🇳🇪|🇳🇫|🇳🇬|🇳🇮|🇳🇱|🇳🇴|🇳🇵|🇳🇷|🇳🇺|🇳🇿|🇴🇲|🇵🇦|🇵🇪|🇵🇫|🇵🇬|🇵🇭|🇵🇰|🇵🇱|🇵🇲|🇵🇳|🇵🇷|🇵🇸|🇵🇹|🇵🇼|🇵🇾|🇶🇦|🇷🇪|🇷🇴|🇷🇸|🇷🇺|🇷🇼|🇸🇦|🇸🇧|🇸🇨|🇸🇩|🇸🇪|🇸🇬|🇸🇭|🇸🇮|🇸🇯|🇸🇰|🇸🇱|🇸🇲|🇸🇳|🇸🇴|🇸🇷|🇸🇸|🇸🇹|🇸🇻|🇸🇽|🇸🇾|🇸🇿|🇹🇦|🇹🇨|🇹🇩|🇹🇫|🇹🇬|🇹🇭|🇹🇯|🇹🇰|🇹🇱|🇹🇲|🇹🇳|🇹🇴|🇹🇷|🇹🇹|🇹🇻|🇹🇼|🇹🇿|🇺🇦|🇺🇬|🇺🇲|🇺🇸|🇺🇾|🇺🇿|🇻🇦|🇻🇨|🇻🇪|🇻🇬|🇻🇮|🇻🇳|🇻🇺|🇼🇫|🇼🇸|🇽🇰|🇾🇪|🇾🇹|🇿🇦|🇿🇲|🇿🇼)?$", remark):
        return False
    
    # If it contains additional text after Server X flag, it's custom
    return True

def update_server_remarks(servers):
    """Update server remarks with auto-numbering and flags"""
    print("🏷️  Updating server remarks...")
    
    # Collect existing remarks to find next available number
    existing_remarks = []
    for server in servers:
        if '#' in server:
            remark = server.split('#', 1)[1].strip()
            existing_remarks.append(remark)
    
    updated_servers = []
    
    for server in servers:
        # Skip servers with custom remarks
        if has_custom_remark(server):
            print(f"🏷️  Keeping custom remark: {server.split('#', 1)[1].strip()}")
            updated_servers.append(server)
            continue
        
        # Get server IP and country
        ip = extract_ip_from_server(server)
        country_code = get_country_code(ip) if ip else ''
        flag = country_code_to_flag(country_code)
        
        # Get next available server number
        next_num = get_next_server_number(existing_remarks)
        existing_remarks.append(f"Server {next_num}")
        
        # Create new remark
        new_remark = f"Server {next_num}"
        if flag:
            new_remark += f" {flag}"
        
        # Update server line
        base_server = server.split('#')[0]
        updated_server = f"{base_server}#{new_remark}"
        updated_servers.append(updated_server)
        
        print(f"🏷️  Updated: Server {next_num} {flag} ({ip or 'unknown IP'})")
    
    return updated_servers

# === Advanced Duplicate Detection Functions ===

def normalize_vless_url(server_line):
    """Normalize VLESS URL by sorting query parameters and removing remarks"""
    try:
        url_part = server_line.split('#')[0]  # Remove remark
        parsed = urlparse(url_part)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        # Sort query parameters
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        query_params.sort()  # sort by key then value
        query = urlencode(query_params, doseq=True)
        normalized = urlunparse((scheme, netloc, path, '', query, ''))
        return normalized
    except Exception as e:
        print(f"Error normalizing VLESS URL: {e}")
        return server_line

def normalize_vmess_url(server_line):
    """Normalize VMess URL by sorting JSON keys and standardizing values"""
    try:
        base64_part = server_line[8:].split('#')[0]  # Remove remark
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
    except Exception as e:
        print(f"Error normalizing VMess URL: {e}")
        return server_line

def normalize_generic_url(server_line):
    """Normalize SS/Trojan URLs by sorting query parameters"""
    try:
        url_part = server_line.split('#')[0]  # Remove remark
        parsed = urlparse(url_part)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        # Sort query parameters
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        query_params.sort()
        query = urlencode(query_params, doseq=True)
        normalized = urlunparse((scheme, netloc, path, '', query, ''))
        return normalized
    except Exception as e:
        print(f"Error normalizing URL: {e}")
        return server_line

def extract_server_config(server_line):
    """Extract normalized server configuration for duplicate detection"""
    try:
        server_line = server_line.strip()
        
        if server_line.startswith('vmess://'):
            return normalize_vmess_url(server_line)
        elif server_line.startswith('vless://'):
            return normalize_vless_url(server_line)
        elif server_line.startswith('ss://'):
            return normalize_generic_url(server_line)
        elif server_line.startswith('trojan://'):
            return normalize_generic_url(server_line)
        else:
            # For other protocols, use the config without remarks
            return server_line.split('#')[0].strip().lower()
            
    except Exception as e:
        print(f"Error parsing server config: {e}")
        return server_line

def remove_duplicates(servers):
    """Remove duplicate servers based on normalized configuration"""
    seen_configs = {}
    unique_servers = []
    duplicates_found = []
    
    for server in servers:
        if not server.strip():
            continue
            
        config_key = extract_server_config(server)
        
        if config_key in seen_configs:
            # Duplicate found
            duplicates_found.append({
                'original': seen_configs[config_key],
                'duplicate': server.strip()
            })
            print(f"🔍 Advanced duplicate found:")
            print(f"   Original: {seen_configs[config_key][:80]}...")
            print(f"   Duplicate: {server.strip()[:80]}...")
        else:
            # New unique server
            seen_configs[config_key] = server.strip()
            unique_servers.append(server.strip())
    
    if duplicates_found:
        print(f"📋 Removed {len(duplicates_found)} duplicate servers (advanced detection)")
        for dup in duplicates_found:
            original_remark = dup['original'].split('#')[-1] if '#' in dup['original'] else 'No remark'
            duplicate_remark = dup['duplicate'].split('#')[-1] if '#' in dup['duplicate'] else 'No remark'
            print(f"   Kept: {original_remark}")
            print(f"   Removed: {duplicate_remark}")
    else:
        print("✅ No duplicates found (advanced detection)")
    
    return unique_servers

# === Existing Functions (Unchanged) ===

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

# === Fake Server Detection ===

def is_fake_server(server_line):
    """Check if a server is a fake server (should not be validated)"""
    fake_indicators = [
        "127.0.0.1",
        "localhost", 
        "fake",
        "Fake Server",
        "fakepas",
        "12345678-1234-1234-1234-123456789",  # fake UUIDs
        "YWVzLTI1Ni1nY206ZmFrZXBhc3N3b3Jk"  # fake SS config
    ]
    
    server_lower = server_line.lower()
    for indicator in fake_indicators:
        if indicator.lower() in server_lower:
            return True
    return False

# === Server Validation Function ===

def validate_server(server_line):
    """Test if a server is reachable"""
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
            # Test connection with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # 5 second timeout
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

# === Quarantine Functions ===

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
    # Use advanced duplicate detection
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
    """Try to recover servers from non_working.txt"""
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

# === Test Function ===

def test_quarantine_system():
    """Test the quarantine system with server validation (protects fake servers)"""
    print("🧪 Testing quarantine system...")
    
    # Step 1: Validate all servers in main.txt (except fake ones)
    main_servers = load_main_servers()
    working_servers = []
    
    for server in main_servers:
        # Skip validation for fake servers
        if is_fake_server(server):
            print(f"⚪ Skipping fake server: {server}")
            working_servers.append(server)
        elif validate_server(server):
            working_servers.append(server)
        else:
            print(f"🚫 Moving to quarantine: {server}")
            move_server_to_non_working(server)
    
    # Step 2: Update main.txt with working servers (including fake ones)
    if len(working_servers) < len(main_servers):
        save_main_servers(working_servers)
        print(f"💾 Updated main.txt: {len(main_servers)} → {len(working_servers)} servers")
    
    # Step 3: Show quarantine status
    non_working = load_non_working()
    print(f"📋 Servers in quarantine: {len(non_working)}")
    for line in non_working:
        server, dt = parse_non_working_line(line)
        if server and dt:
            remark = server.split('#')[-1] if '#' in server else 'No remark'
            print(f"   - {remark} (since {dt})")

# === Main Update Function ===

def update_all_subscriptions():
    """Update all subscription files with servers from main.txt"""
    
    # Step 1: Clean up non_working.txt (remove servers over 3 days)
    cleanup_non_working()
    
    # Step 2: Try to recover servers from quarantine
    process_non_working_recovery()

    # Step 3: Read servers from main.txt
    try:
        with open('main.txt', 'r', encoding='utf-8') as f:
            all_servers = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print("❌ main.txt not found")
        return

    print(f"📖 Read {len(all_servers)} servers from main.txt")

    # Step 4: Update server remarks with auto-numbering and flags
    all_servers = update_server_remarks(all_servers)

    # Step 5: Remove duplicates (now with advanced detection)
    unique_servers = remove_duplicates(all_servers)

    # Step 6: Update main.txt if changes were made
    if len(unique_servers) != len(all_servers) or all_servers != unique_servers:
        print(f"💾 Updating main.txt with remarks and duplicate removal")
        with open('main.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_servers) + '\n')

    # Step 7: Get blocked users
    blocked_users = get_blocked_users()

    # Step 8: Process subscription files
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
    
    # Test quarantine system first (validates servers, protects fake ones)
    test_quarantine_system()
    
    # Then run normal update
    update_all_subscriptions()
    print("✨ Update process completed!")
