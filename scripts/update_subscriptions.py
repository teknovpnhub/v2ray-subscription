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
import yaml

# === Server Remark and Flag Functions ===

def extract_ip_from_server(server_line):
    """Extract IP address or hostname from server URL.
    Supports: vless, vmess, trojan, ss, hysteria, hysteria2"""
    try:
        if server_line.startswith(('vless://', 'trojan://', 'hysteria://', 'hysteria2://')):
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

def get_country_code(ip_or_domain):
    """Get country code for an IP address or domain name using multiple free APIs with fallback.
    Tries providers in order: ipinfo.io (best limits), ip-api.com (backup).
    Returns empty string on failure."""
    if not ip_or_domain:
        return ''
    
    # Provider list with their API endpoints and response parsing
    providers = [
        {
            'name': 'ipinfo.io',
            'url': f'https://ipinfo.io/{ip_or_domain}/country',
            'parse': lambda r: r.text.strip() if r.status_code == 200 else None,
            'needs_key': False
        },
        {
            'name': 'ip-api.com',
            'url': f'http://ip-api.com/json/{ip_or_domain}?fields=countryCode',
            'parse': lambda r: r.json().get('countryCode', '') if r.status_code == 200 else None,
            'needs_key': False
        }
    ]
    
    # Try each provider
    for provider in providers:
        for attempt in range(2):  # 2 attempts per provider
            try:
                response = requests.get(provider['url'], timeout=10)
                
                # Check for rate limiting
                if response.status_code == 429:
                    if attempt < 1:
                        time.sleep(2)
                        continue
                    # Try next provider
                    break
                
                # Parse response
                cc = provider['parse'](response)
                if cc and len(cc) == 2:
                    return cc.upper()
                
                # If successful response but no country code, don't retry
                if response.status_code == 200:
                    break
                    
            except requests.exceptions.Timeout:
                if attempt < 1:
                    time.sleep(1)
                    continue
                # Try next provider
                break
            except requests.exceptions.RequestException:
                if attempt < 1:
                    time.sleep(1)
                    continue
                # Try next provider
                break
            except Exception:
                # Try next provider
                break
    
    return ''

def country_code_to_flag(country_code):
    if not country_code or len(country_code) != 2:
        return ''
    try:
        return chr(0x1F1E6 + ord(country_code[0].upper()) - ord('A')) + \
               chr(0x1F1E6 + ord(country_code[1].upper()) - ord('A'))
    except:
        return ''

def update_server_remarks(servers, flags_enabled=True, auto_rename_enabled=True):
    """Update server remarks based on FLAGS and AUTO_RENAME settings.
    - If flags_enabled=False: skips IP geo lookup (fast).
    - If auto_rename_enabled=False: preserves original server remarks.
    """
    updated_servers = []
    failed_flags = 0
    failed_ips = []
    
    for idx, server in enumerate(servers, 1):
        base_url = server.split('#')[0]
        original_remark = server.split('#', 1)[1].strip() if '#' in server else ""
        
        # Determine country flag if flags are enabled
        flag = ""
        if flags_enabled:
            ip_or_domain = extract_ip_from_server(server)
            cc = get_country_code(ip_or_domain)
            flag = country_code_to_flag(cc)
            if not flag and ip_or_domain:
                failed_flags += 1
                if len(failed_ips) < 5:
                    failed_ips.append(ip_or_domain)
            time.sleep(0.5)
        
        # Determine new remark based on auto_rename_enabled
        if auto_rename_enabled:
            if "---" in original_remark:
                _, custom = original_remark.split("---", 1)
                new_remark = f"Server {idx} {flag}--- {custom.strip()}".strip()
            else:
                new_remark = f"Server {idx} {flag}".strip()
        else:
            # Keep original remark
            clean_original = strip_flag_from_name(original_remark)
            if flag:
                new_remark = f"{clean_original} {flag}".strip()
            else:
                new_remark = clean_original

        if server.startswith('vmess://'):
            try:
                base64_part = server[8:].split('#')[0]
                missing_padding = len(base64_part) % 4
                if missing_padding:
                    base64_part += '=' * (4 - missing_padding)
                
                decoded = base64.b64decode(base64_part).decode('utf-8')
                config = json.loads(decoded)
                
                if config.get('v') is None:
                    config['v'] = "2"
                
                if auto_rename_enabled or flag:
                    if not auto_rename_enabled:
                        curr_ps = config.get('ps', '')
                        clean_ps = strip_flag_from_name(curr_ps)
                        config['ps'] = f"{clean_ps} {flag}".strip() if flag else clean_ps
                    else:
                        config['ps'] = new_remark
                
                new_json = json.dumps(config, separators=(',', ':'), ensure_ascii=False)
                new_base64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
                updated_servers.append(f"vmess://{new_base64}")
            except Exception:
                updated_servers.append(f"{base_url}#{new_remark}" if new_remark else base_url)
        else:
            updated_servers.append(f"{base_url}#{new_remark}" if new_remark else base_url)
    
    if flags_enabled and failed_flags > 0:
        try:
            failed_info = f" (examples: {', '.join(failed_ips[:3])})" if failed_ips else ""
            print(f"⚠️ Could not add flags to {failed_flags} servers (IP lookup failed){failed_info}")
        except UnicodeEncodeError:
            print(f"Warning: Could not add flags to {failed_flags} servers (IP lookup failed)")
    
    return updated_servers

def strip_flag_from_name(name):
    """Strip country flag emojis (regional indicator symbols) from proxy name."""
    if not name:
        return ""
    return re.sub(r'[\U0001F1E6-\U0001F1FF]{2}', '', str(name)).strip()

def is_yaml_file(filepath):
    """Check if file path or name is a YAML file (by extension or content inspection)."""
    if not filepath:
        return False
    if str(filepath).lower().endswith(('.yaml', '.yml')):
        return True
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for _ in range(10):
                    line = f.readline()
                    if not line:
                        break
                    stripped = line.strip()
                    if stripped.startswith('proxies:') or stripped.startswith('proxy-groups:'):
                        return True
        except Exception:
            pass
    return False

def get_fake_yaml_config(expired_msg=None):
    """Return a fake YAML configuration indicating an expired subscription."""
    fake_remark = expired_msg.strip() if expired_msg and expired_msg.strip() else "اشتراک شما تمام شده است لطفا اشتراک خود را تمدید کنید"
    return {
        "proxies": [
            {
                "name": fake_remark,
                "type": "vless",
                "server": "127.0.0.1",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "cipher": "auto",
                "udp": False,
                "tls": False
            }
        ],
        "proxy-groups": [
            {
                "name": "WARP",
                "type": "select",
                "proxies": [fake_remark]
            }
        ]
    }

def update_yaml_remarks(yaml_data, flags_enabled=True, auto_rename_enabled=True):
    """Update proxy names with country flags in YAML configurations.
    - If flags_enabled=False: strips flags and skips IP lookup.
    """
    if not isinstance(yaml_data, dict):
        return yaml_data
    
    proxies = yaml_data.get('proxies', [])
    if not isinstance(proxies, list):
        return yaml_data
    
    name_map = {}
    failed_flags = 0
    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        original_name = str(proxy.get('name', ''))
        base_name = strip_flag_from_name(original_name)
        
        if flags_enabled:
            ip_or_domain = proxy.get('server')
            cc = get_country_code(ip_or_domain)
            flag = country_code_to_flag(cc)
            if flag:
                new_name = f"{base_name} {flag}"
            else:
                new_name = base_name
                if ip_or_domain:
                    failed_flags += 1
            time.sleep(0.5)
        else:
            new_name = base_name
            
        proxy['name'] = new_name
        if original_name != new_name:
            name_map[original_name] = new_name
            name_map[base_name] = new_name
    
    # Update proxy-groups to reflect updated proxy names
    proxy_groups = yaml_data.get('proxy-groups', [])
    if isinstance(proxy_groups, list):
        for group in proxy_groups:
            if isinstance(group, dict) and 'proxies' in group and isinstance(group['proxies'], list):
                group['proxies'] = [name_map.get(p, p) for p in group['proxies']]
    
    if flags_enabled and failed_flags > 0:
        try:
            print(f"⚠️ Could not add flags to {failed_flags} YAML proxies (IP lookup failed)")
        except UnicodeEncodeError:
            print(f"Warning: Could not add flags to {failed_flags} YAML proxies (IP lookup failed)")
        
    return yaml_data

# === Enhanced User Management Functions ===

USER_LIST_FILE = 'user_list.txt'
BLOCKED_SYMBOL = '🚫'
IRAN_TZ = pytz.timezone('Asia/Tehran')

# Last known state of user_list for detecting manual changes
LAST_USER_STATE_FILE = 'last_user_state.json'

def save_user_state(users=None):
    """Save current state of users for detecting manual changes later"""
    if users is None:
        users = load_user_list()
    
    # Build a dict of username -> full line for easy comparison
    state = {}
    usernames = []
    for line in users:
        username = extract_username_from_line(line)
        if username:
            state[username] = line
            usernames.append(username)
    
    # Also save the order of usernames
    data = {
        "usernames": usernames,
        "lines": state,
        "timestamp": get_iran_time().strftime("%Y-%m-%d %H:%M")
    }
    
    with open(LAST_USER_STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def detect_manual_changes():
    """Detect manual changes to user_list.txt without command flags"""
    if not os.path.exists(LAST_USER_STATE_FILE):
        # No previous state, just save current state
        save_user_state()
        return
    
    # Load previous state
    with open(LAST_USER_STATE_FILE, 'r', encoding='utf-8') as f:
        last_state = json.load(f)
    
    last_usernames = set(last_state["usernames"])
    last_lines = last_state["lines"]
    
    # Load current state
    current_users = load_user_list()
    current_usernames = set()
    current_lines = {}
    # Track manually modified users to create backups
    manual_modified_users = set()
    # Track if any manual changes were made
    any_manual_changes = False
    
    for line in current_users:
        # Skip processing lines with command flags, as these will be handled elsewhere
        if re.search(r'---(b|ub|d|m|r|es|msg|src)\b', line, re.IGNORECASE):
            continue
            
        username = extract_username_from_line(line)
        if username:
            current_usernames.add(username)
            current_lines[username] = line
    
    # Find manually deleted users
    deleted = last_usernames - current_usernames
    if deleted:
        any_manual_changes = True  # Users were manually deleted
    for username in deleted:
        log_user_history(username, "manual_delete", "User manually removed")
    
    # Find manually added users
    added = current_usernames - last_usernames
    if added:
        any_manual_changes = True  # Users were manually added
    for username in added:
        user_line = current_lines[username]
        # Only include the actual line in the details, log_user_history will handle notes
        details = f"Line: {user_line}"
        log_user_history(username, "manual_add", details)
        manual_modified_users.add(username)
    
    # Find modified users (same username but different line content)
    modified = False
    for username in last_usernames.intersection(current_usernames):
        if last_lines[username] != current_lines.get(username, ''):
            modified = True  # Users were manually modified

            old_line = last_lines[username]
            new_line = current_lines.get(username, '')

            # --- Handle manual un-blocking by cleaning old "| blocked" tags ---
            if old_line.startswith(BLOCKED_SYMBOL) and not new_line.startswith(BLOCKED_SYMBOL):
                notes_raw = extract_notes_from_line(new_line)
                if "| blocked" in notes_raw:
                    cleaned_notes = strip_block_dates(notes_raw)
                    user_data = extract_user_data_from_line(new_line)
                    
                    # Rebuild the line with cleaned notes
                    if user_data and cleaned_notes:
                        cleaned_line = f"{username} {user_data} #{cleaned_notes}"
                    elif user_data:
                        cleaned_line = f"{username} {user_data}"
                    elif cleaned_notes:
                        cleaned_line = f"{username} #{cleaned_notes}"
                    else:
                        cleaned_line = username

                    # Update the in-memory representations of the user list
                    current_lines[username] = cleaned_line
                    # Find the index and update the list itself
                    for i, line in enumerate(current_users):
                        if extract_username_from_line(line) == username:
                            current_users[i] = cleaned_line
                            break
                    new_line = cleaned_line # Use the cleaned line for the diff

            # Use difflib to find exact changes
            differ = Differ()
            diff = list(differ.compare([last_lines[username]], [new_line]))
            diff_text = '\n'.join(diff)
            details = f"Changes:\n{diff_text}"
            log_user_history(username, "manual_change", details)
            manual_modified_users.add(username)
    
    # If any manual changes were detected, create a full backup
    if any_manual_changes or modified:
        backup_user_list()
        
    # Backup all manually modified users
    for username in manual_modified_users:
        backup_user(username)
    
    # Move manually modified users to the top of the list
    if manual_modified_users:
        final_users = current_users.copy()
        for username in manual_modified_users:
            final_users = move_user_to_top(final_users, username)
        save_user_list(final_users)
    
    # Save new state for next comparison
    save_user_state(current_users)

def get_iran_time():
    utc_now = datetime.datetime.now(pytz.UTC)
    return utc_now.astimezone(IRAN_TZ)

def load_user_list():
    if not os.path.exists(USER_LIST_FILE):
        return []
    with open(USER_LIST_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def save_user_list(users):
    # Create backup before saving changes
    backup_user_list()

    with open(USER_LIST_FILE, 'w', encoding='utf-8') as f:
        if users:
            f.write('\n'.join(users) + '\n')

def extract_username_from_line(user_line):
    # First remove the blocked symbol if present
    clean_line = user_line.replace(BLOCKED_SYMBOL, '').strip()
    
    # Handle notes by removing everything after #
    if '#' in clean_line:
        clean_line = clean_line.split('#')[0].strip()
    
    # Handle command flags
    if '---' in clean_line:
        before_command = clean_line.split('---')[0].strip()
        username = before_command.split()[0] if before_command.split() else ''
        return username
    else:
        # Just get the first word as username
        username = clean_line.split()[0] if clean_line.split() else clean_line
        return username

def extract_user_data_from_line(user_line):
    clean_line = user_line.replace(BLOCKED_SYMBOL, '').strip()

    # Handle notes by removing everything after #
    # Also remove pipe-separated block dates (they're notes, not user_data)
    if '#' in clean_line:
        clean_line = clean_line.split('#')[0].strip()
    
    # Remove pipe-separated block dates (e.g., "| blocked 2025-10-31")
    if '|' in clean_line:
        clean_line = clean_line.split('|')[0].strip()

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

# === Helper to remove prior block-date tags ===
def strip_block_dates(note: str) -> str:
    """Remove all occurrences of "| blocked YYYY-MM-DD" from a note string."""
    if not note:
        return note
    cleaned = re.sub(r"\s*\|\s*blocked\s+\d{4}-\d{2}-\d{2}", "", note)
    return cleaned.strip()

def extract_custom_message_from_line(line: str) -> str:
    """Extract custom message from line if specified with ---msg or | msg:"""
    if not line:
        return ""
    if '---msg' in line.lower():
        parts = re.split(r'---msg\s*', line, flags=re.IGNORECASE)
        if len(parts) > 1:
            msg_part = parts[1].split('---')[0].split('|')[0].strip()
            if msg_part:
                return msg_part
    match = re.search(r'\|\s*(?:msg|message|پیام|دلیل)[:\s]+([^|#\n]+)', line, re.IGNORECASE)
    if match:
        msg_val = match.group(1).split('---')[0].strip()
        if msg_val:
            return msg_val
    return ""

def strip_custom_messages(note: str) -> str:
    """Remove all occurrences of '| msg: ...' from a note string."""
    if not note:
        return note
    cleaned = re.sub(r"\s*\|\s*(?:msg|message|پیام|دلیل)[:\s]+[^|#\n]*", "", note, flags=re.IGNORECASE)
    return cleaned.strip()

def extract_custom_source_from_line(line: str) -> str:
    """Extract custom server source file if specified with ---src or | src:"""
    if not line:
        return ""
    if '---src' in line.lower():
        parts = re.split(r'---src\s*', line, flags=re.IGNORECASE)
        if len(parts) > 1:
            src_part = parts[1].split('---')[0].split('#')[0].split('|')[0].strip()
            if src_part:
                return src_part.split()[0]
    match = re.search(r'\|\s*(?:src|source)[:\s]+([^|#\n]+)', line, re.IGNORECASE)
    if match:
        src_val = match.group(1).split('---')[0].strip()
        if src_val:
            return src_val.split()[0]
    return ""

def strip_custom_sources(note: str) -> str:
    """Remove all occurrences of '| src: ...' from a note string."""
    if not note:
        return note
    cleaned = re.sub(r"\s*\|\s*(?:src|source)[:\s]+[^|#\n]*", "", note, flags=re.IGNORECASE)
    return cleaned.strip()

def clean_notes_command_tokens(raw_notes: str, custom_msg: str = "", custom_src: str = "") -> str:
    """Safely strip all command flags (---b, ---ub, ---d, ---m, ---r, ---es, ---msg, ---src) and their inline arguments."""
    if not raw_notes:
        return ""
    cleaned = strip_custom_messages(raw_notes)
    cleaned = strip_custom_sources(cleaned)
    cleaned = re.sub(r'\s*\|\s*blocked\s+\d{4}-\d{2}-\d{2}', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'---msg\s+[^|#\n]*', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'---src\s+\S+', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'---es\s+\S+', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'---r\s+\S+', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'---(b|ub|d|m|r|es|msg|src)\b', '', cleaned, flags=re.IGNORECASE)
    if custom_msg:
        cleaned = cleaned.replace(f"sg {custom_msg}", "")
        cleaned = re.sub(re.escape(custom_msg), '', cleaned)
    if custom_src:
        cleaned = re.sub(re.escape(custom_src), '', cleaned)
    cleaned = re.sub(r'\|\s*$', '', cleaned)
    return ' '.join(cleaned.split()).strip()

EXTERNAL_CACHE_DIR = '.external_cache'

def is_external_source(src: str) -> bool:
    """Check if the source is an external URL, a .src.txt file, or contains URLs."""
    if not src or not isinstance(src, str):
        return False
    src_clean = src.strip()
    if src_clean.startswith(('http://', 'https://')):
        return True
    if src_clean.endswith(('.src.txt', '.src', '.sources.txt')) or src_clean.startswith('external'):
        return True
    if os.path.exists(src_clean):
        try:
            with open(src_clean, 'r', encoding='utf-8') as f:
                for line in f:
                    line_s = line.strip()
                    if line_s.startswith(('http://', 'https://')):
                        return True
        except Exception:
            pass
    return False

def fetch_subscription_from_url(url: str, timeout: int = 15):
    """Fetch subscription content from an external URL.
    Returns (content, is_yaml).
    Handles Base64, Clash YAML, and raw proxy links with local caching.
    """
    if not os.path.exists(EXTERNAL_CACHE_DIR):
        os.makedirs(EXTERNAL_CACHE_DIR, exist_ok=True)
    
    import hashlib
    url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()
    cache_path = os.path.join(EXTERNAL_CACHE_DIR, f"{url_hash}.cache")

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 ClashMeta/1.18.0 v2rayNG/1.8.12 Karing/1.0.0'
    }

    raw_text = None
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200 and resp.text.strip():
            raw_text = resp.text.strip()
            with open(cache_path, 'w', encoding='utf-8') as f:
                f.write(raw_text)
    except Exception as e:
        print(f"⚠️ Network error fetching external URL {url}: {e}")

    # Fallback to local cache if network request failed
    if not raw_text and os.path.exists(cache_path):
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                raw_text = f.read().strip()
            print(f"ℹ️ Loaded external subscription from cache for: {url}")
        except Exception:
            pass

    if not raw_text:
        return [], False

    # 1. Check if raw_text is direct Clash/Mihomo YAML
    try:
        parsed_yaml = yaml.safe_load(raw_text)
        if isinstance(parsed_yaml, dict) and ('proxies' in parsed_yaml or 'proxy-groups' in parsed_yaml):
            return parsed_yaml, True
    except Exception:
        pass

    # 2. Check if raw_text is Base64 encoded
    content_to_parse = raw_text
    try:
        decoded_bytes = base64.b64decode(raw_text.encode('utf-8'), validate=False)
        decoded_candidate = decoded_bytes.decode('utf-8', errors='ignore')
        if any(proto in decoded_candidate for proto in ['vmess://', 'vless://', 'ss://', 'trojan://', 'tuic://', 'hysteria://', 'hysteria2://', 'wireguard://']):
            content_to_parse = decoded_candidate
    except Exception:
        pass

    # 3. Check again if decoded content is YAML
    try:
        parsed_yaml = yaml.safe_load(content_to_parse)
        if isinstance(parsed_yaml, dict) and ('proxies' in parsed_yaml or 'proxy-groups' in parsed_yaml):
            return parsed_yaml, True
    except Exception:
        pass

    # 4. Parse as lines of server URLs
    servers = []
    for line in content_to_parse.splitlines():
        line_clean = line.strip()
        if not line_clean or line_clean.startswith('#'):
            continue
        if any(line_clean.startswith(p) for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'tuic://', 'hysteria://', 'hysteria2://', 'wireguard://', 'wg://', 'socks5://', 'http://', 'https://']):
            servers.append(line_clean)
        elif len(line_clean) > 10 and '://' in line_clean:
            servers.append(line_clean)
    
    return servers, False

def load_external_source(src: str):
    """Load and combine servers from an external URL or an external source file (.src.txt).
    Returns (content, is_yaml).
    """
    if not src:
        return [], False
    
    src_clean = src.strip()
    # If direct URL
    if src_clean.startswith(('http://', 'https://')):
        return fetch_subscription_from_url(src_clean)
    
    # If file containing URLs or server configs
    if not os.path.exists(src_clean):
        # Create empty template if it doesn't exist
        with open(src_clean, 'w', encoding='utf-8') as f:
            f.write("# Put your external subscription link(s) below:\n# https://provider.com/sub/token123\n")
        return [], False
    
    urls = []
    direct_servers = []
    with open(src_clean, 'r', encoding='utf-8') as f:
        for line in f:
            line_clean = line.strip()
            if not line_clean or line_clean.startswith('#'):
                continue
            if line_clean.startswith(('http://', 'https://')):
                urls.append(line_clean)
            elif any(line_clean.startswith(p) for p in ['vless://', 'vmess://', 'ss://', 'trojan://', 'tuic://', 'hysteria://', 'hysteria2://', 'wireguard://']):
                direct_servers.append(line_clean)
    
    all_servers = list(direct_servers)
    yaml_configs = []

    for url in urls:
        content, is_yaml = fetch_subscription_from_url(url)
        if is_yaml and isinstance(content, dict):
            yaml_configs.append(content)
        elif isinstance(content, list):
            all_servers.extend(content)
    
    if yaml_configs and not all_servers:
        base_yaml = yaml_configs[0]
        for extra_yaml in yaml_configs[1:]:
            extra_proxies = extra_yaml.get('proxies', [])
            if isinstance(extra_proxies, list):
                base_yaml.setdefault('proxies', []).extend(extra_proxies)
        return base_yaml, True
    
    return all_servers, False

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

def generate_unique_username(base_username):
    """
    Generate a unique username by adding a numeric suffix if needed.
    For example, if 'ahmad' exists, it will try 'ahmad1', 'ahmad2', etc.
    """
    users = load_user_list()
    existing_usernames = [extract_username_from_line(user) for user in users]
    
    # Check if the base username is already unique
    if base_username not in existing_usernames:
        return base_username
    
    # Try adding numeric suffixes until we find a unique username
    counter = 1
    while True:
        new_username = f"{base_username}{counter}"
        if new_username not in existing_usernames:
            return new_username
        counter += 1

def add_user_to_list(username, user_data=''):
    users = load_user_list()
    # Extract just the usernames for comparison
    existing_usernames = [extract_username_from_line(user) for user in users]
    
    # Debug print to help identify the issue
    print(f"Adding user via add_user_to_list: {username}")
    print(f"Existing usernames: {existing_usernames}")
    
    original_username = username
    # Clean the username from any notes or commands before comparison
    clean_username = username.split('#')[0].strip() if '#' in username else username
    clean_username = clean_username.split('---')[0].strip() if '---' in clean_username else clean_username
    clean_username = clean_username.split()[0] if ' ' in clean_username else clean_username
    
    # If username already exists, generate a unique one
    if clean_username in existing_usernames:
        username = generate_unique_username(clean_username)
        # Log that the username was automatically changed
        log_user_history(username, "auto_renamed", f"Automatically renamed from {original_username} due to duplicate")
        print(f"⚠️ Username {original_username} already exists, using {username} instead")
    
    new_entry = f"{username} {user_data}" if user_data else username
    # Add the new user to the list
    users.append(new_entry)
    # Move the new user to the top
    users = move_user_to_top(users, username)
    # Create a full backup when adding a new user
    backup_user_list()
    save_user_list(users)
    # Create individual backup for this new user
    backup_user(username)
    print(f"📝 Added new user: {new_entry}")
    
    # Create subscription file for the user
    create_subscription_file(username)
    
    # Pass user_data directly to log_user_history
    # The log_user_history function will handle formatting notes correctly
    log_user_history(username, "added", user_data)
    return True

def create_subscription_file(username):
    subscription_dir = 'subscriptions'
    if not os.path.exists(subscription_dir):
        os.makedirs(subscription_dir)
    sub_file = os.path.join(subscription_dir, f"{username}.txt")
    if not os.path.exists(sub_file):
        with open(sub_file, 'w', encoding='utf-8') as f:
            f.write('')
        try:
            print(f"📄 Created subscription file: {username}.txt")
        except UnicodeEncodeError:
            print(f"[OK] Created subscription file: {username}.txt")
        return True
    else:
        try:
            print(f"⚠️  Subscription file already exists: {username}.txt")
        except UnicodeEncodeError:
            print(f"[WARN] Subscription file already exists: {username}.txt")
        return False

def rename_subscription_file(old_username, new_username):
    subscription_dir = 'subscriptions'
    old_file = os.path.join(subscription_dir, f"{old_username}.txt")
    new_file = os.path.join(subscription_dir, f"{new_username}.txt")
    
    if os.path.exists(old_file):
        # If the new file already exists, generate a unique username
        if os.path.exists(new_file):
            original_new_username = new_username
            new_username = generate_unique_username(new_username)
            new_file = os.path.join(subscription_dir, f"{new_username}.txt")
            try:
                print(f"⚠️ Subscription file {original_new_username}.txt already exists, using {new_username}.txt instead")
            except UnicodeEncodeError:
                print(f"[WARN] Subscription file {original_new_username}.txt already exists, using {new_username}.txt instead")
            log_user_history(new_username, "auto_renamed", f"Automatically renamed from {original_new_username} due to duplicate subscription file")
            
        os.rename(old_file, new_file)
        try:
            print(f"📄 Renamed subscription file: {old_username}.txt → {new_username}.txt")
        except UnicodeEncodeError:
            print(f"[OK] Renamed subscription file: {old_username}.txt -> {new_username}.txt")
        return new_username  # Return the potentially modified username
    else:
        try:
            print(f"⚠️ Subscription file not found: {old_username}.txt")
        except UnicodeEncodeError:
            print(f"[WARN] Subscription file not found: {old_username}.txt")
        return new_username  # Return the original username

def move_user_to_top(users, username):
    """Move a user to the top of the user list."""
    user_line = None
    remaining_users = []
    
    # Find the user's line and collect all other users
    for line in users:
        if extract_username_from_line(line) == username:
            user_line = line
        else:
            remaining_users.append(line)
    
    # If user was found, add them to the top
    if user_line:
        return [user_line] + remaining_users
    
    # If user wasn't found, return original list
    return users

def process_user_commands():
    users = load_user_list()

    # --- Pre-clean: remove stale "| blocked" notes from any un-blocked user ---
    precleaned_users = []
    for line in users:
        if not line.startswith(BLOCKED_SYMBOL) and "| blocked" in line:
            notes_raw = extract_notes_from_line(line)
            cleaned_notes = strip_block_dates(notes_raw)
            if cleaned_notes != notes_raw:
                username = extract_username_from_line(line)
                user_data = extract_user_data_from_line(line)
                if user_data and cleaned_notes:
                    cleaned_line = f"{username} {user_data} #{cleaned_notes}"
                elif user_data:
                    cleaned_line = f"{username} {user_data}"
                elif cleaned_notes:
                    cleaned_line = f"{username} #{cleaned_notes}"
                else:
                    cleaned_line = username
                precleaned_users.append(cleaned_line)
                continue  # skip adding original line
        precleaned_users.append(line)

    users = precleaned_users  # work with cleaned list for the rest of the function
    updated_users = []
    blocked_users = set()
    unblocked_users = set()
    deleted_users = set()
    new_users = set()
    renamed_users = {}
    # Track modified users to create backups
    modified_users = set()
    # Track if any commands were processed
    any_commands_processed = False
    # Track users that need to be moved to the top
    users_to_top = set()
    
    for user_line in users:
        # 1. Delete command (---d)
        if re.search(r'---d\b', user_line, re.IGNORECASE):
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            deleted_users.add(username)
            log_user_history(username, "removed", "User deleted")
            continue

        # 2. Add user command (---m)
        if re.search(r'---m\b', user_line, re.IGNORECASE):
            any_commands_processed = True
            line_without_m = re.sub(r'---m\b', '', user_line, flags=re.IGNORECASE).strip()
            username = extract_username_from_line(line_without_m)
            cleaned_line = line_without_m.split('---')[0].split('|')[0].strip()
            user_data = extract_user_data_from_line(cleaned_line)
            raw_notes = extract_notes_from_line(line_without_m)
            
            if not username:
                username = generate_unique_username("customer")
                try:
                    print(f"\u2699\ufe0f Auto-generated username: {username}")
                except UnicodeEncodeError:
                    print(f"[OK] Auto-generated username: {username}")
            
            original_username = username
            existing_usernames = [extract_username_from_line(u) for u in users if u is not user_line]
            existing_updated_usernames = [extract_username_from_line(u) for u in updated_users]
            renamed_new_usernames = set(renamed_users.values())
            existing_new_usernames = new_users.copy()
            
            if username in existing_updated_usernames or username in existing_usernames or username in renamed_new_usernames or username in existing_new_usernames:
                username = generate_unique_username(username)
                log_user_history(username, "auto_renamed", f"Automatically renamed from {original_username} due to duplicate")
                try:
                    print(f"⚠️ Username {original_username} already exists, using {username} instead")
                except UnicodeEncodeError:
                    print(f"[WARN] Username {original_username} already exists, using {username} instead")
            
            new_users.add(username)
            details = user_data if user_data else ""
            log_user_history(username, "added", details)
            create_subscription_file(username)
            
            # Check for expiry on new user (---es)
            if re.search(r'---es\b', user_line, re.IGNORECASE):
                parts = re.split(r'---es\b', user_line, flags=re.IGNORECASE)
                if len(parts) > 1:
                    time_part = parts[1].split('#')[0].split('---')[0].strip()
                    target_datetime = parse_relative_datetime(time_part)
                    if target_datetime:
                        formatted_expiry = format_expiry_datetime(target_datetime)
                        log_user_history(username, "expiry_set", f"{formatted_expiry}")
                        user_data = formatted_expiry

            custom_src = extract_custom_source_from_line(user_line)
            custom_msg = extract_custom_message_from_line(user_line)
            notes = clean_notes_command_tokens(raw_notes, custom_msg=custom_msg, custom_src=custom_src)
            if custom_src and custom_src.lower() not in ['default', 'none', 'reset', 'clear', 'off']:
                notes = f"{notes} | src: {custom_src}" if notes else f"| src: {custom_src}"
            if custom_msg and custom_msg.lower() not in ['default', 'none', 'reset', 'clear', 'off', 'del']:
                notes = f"{notes} | msg: {custom_msg}" if notes else f"| msg: {custom_msg}"

            notes_with_hash = f"#{notes}" if notes else ""
            if user_data and notes_with_hash:
                updated_line = f"{username} {user_data} {notes_with_hash}"
            elif user_data:
                updated_line = f"{username} {user_data}"
            elif notes_with_hash:
                updated_line = f"{username} {notes_with_hash}"
            else:
                updated_line = username
            updated_users.append(updated_line)
            users_to_top.add(username)
            continue

        # 3. Rename command (---r)
        if re.search(r'---r\b', user_line, re.IGNORECASE):
            any_commands_processed = True
            old_username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            command_part = re.split(r'---r\b', user_line, flags=re.IGNORECASE)[1]
            if '#' in command_part:
                command_part = command_part.split('#')[0]
            new_username = command_part.strip().split()[0] if command_part.strip() else ''
            notes = clean_notes_command_tokens(extract_notes_from_line(user_line))
            if new_username and new_username != old_username:
                existing_usernames = [extract_username_from_line(u) for u in users]
                existing_updated_usernames = [extract_username_from_line(u) for u in updated_users]
                renamed_new_usernames = set(renamed_users.values())
                if old_username in renamed_users.values():
                    updated_users.append(user_line)
                    continue
                
                if new_username in existing_usernames or new_username in existing_updated_usernames or new_username in renamed_new_usernames or new_username in new_users:
                    original_new_username = new_username
                    new_username = generate_unique_username(new_username)
                    log_user_history(old_username, "rename_target_conflict", f"Target username {original_new_username} already exists, using {new_username} instead")
                    try:
                        print(f"⚠️ Rename target {original_new_username} already exists, using {new_username} instead")
                    except UnicodeEncodeError:
                        print(f"[WARN] Rename target {original_new_username} already exists, using {new_username} instead")
                renamed_users[old_username] = new_username
                modified_users.add(old_username)
                users_to_top.add(new_username)
                log_user_history(old_username, "renamed", f"to {new_username}")
                symbol = BLOCKED_SYMBOL if user_line.startswith(BLOCKED_SYMBOL) else ''
                
                actual_new_username = rename_subscription_file(old_username, new_username)
                if actual_new_username != new_username:
                    new_username = actual_new_username
                    renamed_users[old_username] = new_username
                    users_to_top.add(new_username)
                
                if user_data and notes:
                    updated_line = f"{symbol}{new_username} {user_data} #{notes}"
                elif user_data:
                    updated_line = f"{symbol}{new_username} {user_data}"
                elif notes:
                    updated_line = f"{symbol}{new_username} #{notes}"
                else:
                    updated_line = f"{symbol}{new_username}"
                updated_users.append(updated_line)
            else:
                updated_users.append(user_line)
            continue

        # 4. General Command Processor (Handles ---ub, ---b, ---msg, ---src, ---es individually or combined)
        has_unblock = bool(re.search(r'---ub\b', user_line, re.IGNORECASE))
        has_block = bool(re.search(r'---b\b', user_line, re.IGNORECASE))
        has_msg = bool(re.search(r'---msg\b', user_line, re.IGNORECASE))
        has_src = bool(re.search(r'---src\b', user_line, re.IGNORECASE))
        has_es = bool(re.search(r'---es\b', user_line, re.IGNORECASE))

        if has_unblock or has_block or has_msg or has_src or has_es:
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            modified_users.add(username)
            users_to_top.add(username)

            # Determine blocked status (---ub overrides ---b)
            if has_unblock:
                is_blocked = False
                unblocked_users.add(username)
                log_user_history(username, "unblocked", "")
            elif has_block:
                is_blocked = True
                blocked_users.add(username)
            else:
                is_blocked = user_line.startswith(BLOCKED_SYMBOL)
                if is_blocked:
                    blocked_users.add(username)

            # Handle expiry (---es)
            cleaned_line = user_line.split('---')[0].split('|')[0].strip()
            user_data = extract_user_data_from_line(cleaned_line)
            if has_es:
                parts = re.split(r'---es\b', user_line, flags=re.IGNORECASE)
                if len(parts) > 1:
                    time_part = parts[1].split('#')[0].split('---')[0].strip()
                    target_datetime = parse_relative_datetime(time_part)
                    if target_datetime:
                        formatted_expiry = format_expiry_datetime(target_datetime)
                        log_user_history(username, "expiry_set", f"{formatted_expiry}")
                        user_data = formatted_expiry

            custom_msg = extract_custom_message_from_line(user_line)
            custom_src = extract_custom_source_from_line(user_line)
            raw_notes = extract_notes_from_line(user_line)
            notes = clean_notes_command_tokens(raw_notes, custom_msg=custom_msg, custom_src=custom_src)

            if is_blocked:
                # Keep existing block date if not explicitly re-blocking
                block_date_match = re.search(r'\|\s*blocked\s+(\d{4}-\d{2}-\d{2})', user_line, re.IGNORECASE)
                block_date = block_date_match.group(1) if (block_date_match and not has_block) else get_iran_time().strftime("%Y-%m-%d")
                date_note = f"| blocked {block_date}"
                notes = f"{notes} {date_note}" if notes else date_note
                if has_block:
                    details = f"{date_note} | msg: {custom_msg}" if custom_msg else date_note
                    log_user_history(username, "blocked", details)

            if custom_src and custom_src.lower() not in ['default', 'none', 'reset', 'clear', 'off']:
                notes = f"{notes} | src: {custom_src}" if notes else f"| src: {custom_src}"

            if custom_msg and custom_msg.lower() not in ['default', 'none', 'reset', 'clear', 'off', 'del']:
                notes = f"{notes} | msg: {custom_msg}" if notes else f"| msg: {custom_msg}"

            prefix = BLOCKED_SYMBOL if is_blocked else ""
            notes_with_hash = f"#{notes}" if notes else ""
            if user_data and notes_with_hash:
                updated_line = f"{prefix}{username} {user_data} {notes_with_hash}"
            elif user_data:
                updated_line = f"{prefix}{username} {user_data}"
            elif notes_with_hash:
                updated_line = f"{prefix}{username} {notes_with_hash}"
            else:
                updated_line = f"{prefix}{username}"
            updated_users.append(updated_line)
        else:
            # Default: keep line as-is
            updated_users.append(user_line)
    
    # Move modified users to the top (in reverse order to maintain priority)
    # We process in reverse order so that the first user to be moved to the top
    # will end up at the very top
    final_users = updated_users.copy()
    for username in users_to_top:
        final_users = move_user_to_top(final_users, username)
    
    # after processing all commands
    # Save new state after command processing
    save_user_state(final_users)
    
    # Create a backup if any commands were processed
    if any_commands_processed:
        backup_user_list()
    
    save_user_list(final_users)
    
    # Create individual backups for each modified user
    for username in modified_users:
        backup_user(username)
    
    # Also backup new usernames from renamed users
    for old_username, new_username in renamed_users.items():
        backup_user(new_username)

    # --- Rebuild blocked_users.txt with notes (including block date) ---
    # First, collect blocked lines from final_users
    blocked_lines_dict = {}
    for line in final_users:
        if line.startswith(BLOCKED_SYMBOL):
            entry = line.lstrip(BLOCKED_SYMBOL).lstrip()
            uname = extract_username_from_line(entry)
            blocked_lines_dict[uname] = entry  # includes pipe note if present

    # Order: freshly blocked first (keep users order in `blocked_users` set), then remaining
    ordered_blocked = []
    for uname in blocked_users:
        if uname in blocked_lines_dict:
            ordered_blocked.append(blocked_lines_dict.pop(uname))
    # Append the rest preserving their appearance order in final_users
    for entry in blocked_lines_dict.values():
        ordered_blocked.append(entry)

    with open('blocked_users.txt', 'w', encoding='utf-8') as f:
        for entry in ordered_blocked:
            f.write(f"{entry}\n")

    existing_blocked = get_blocked_users()
    if blocked_users:
        all_blocked = existing_blocked.union(blocked_users)
    else:
        all_blocked = existing_blocked
    if unblocked_users:
        all_blocked = all_blocked - unblocked_users
    if deleted_users:
        all_blocked = all_blocked - deleted_users
    # We already wrote the full blocked lines (including notes) earlier. Do not
    # overwrite them with username-only lines.  If we need to ensure order, we
    # could rebuild the list including notes, but for now we keep the first
    # write intact to preserve information.
    subscription_dir = 'subscriptions'
    for username in deleted_users:
        sub_file = os.path.join(subscription_dir, f"{username}.txt")
        if os.path.exists(sub_file):
            os.remove(sub_file)

# === BLOCKED USERS FILE COMMANDS ===

def process_blocked_users_commands():
    """Allow admin to put command flags (---ub / ---d) inside blocked_users.txt.
    The function will read blocked_users.txt, process any directives, sync changes
    back to user_list.txt, and rewrite blocked_users.txt without the flags.
    
    Note: ---b (block) command is NOT supported here. Use user_list.txt with ---b instead.
    This file is a shortcut for finding blocked users and unblocking/deleting easily.
    """
    blocked_file = 'blocked_users.txt'
    if not os.path.exists(blocked_file):
        return  # nothing to do

    with open(blocked_file, 'r', encoding='utf-8') as f:
        raw_lines_original = [ln.rstrip() for ln in f if ln.strip()]

    # Deduplicate any repeated usernames, preferring lines that contain a pipe annotation
    dedup_dict = {}
    for ln in raw_lines_original:
        uname = extract_username_from_line(ln)
        if uname in dedup_dict:
            # Prefer the line that has a '|' annotation (more information)
            if '|' in ln and '|' not in dedup_dict[uname]:
                dedup_dict[uname] = ln
        else:
            dedup_dict[uname] = ln

    raw_lines = list(dedup_dict.values())

    # If duplicates were removed, rewrite the cleaned list immediately (before command processing)
    if len(raw_lines) != len(raw_lines_original):
        with open(blocked_file, 'w', encoding='utf-8') as f:
            for l in raw_lines:
                f.write(f"{l}\n")

    if not raw_lines:
        return

    to_unblock = {}
    to_delete = set()
    keep_plain = []  # lines to keep as-is (no command flags, already cleaned)
    commands_found = False

    for line in raw_lines:
        if '---ub' in line:
            username = extract_username_from_line(line)
            note = extract_notes_from_line(line)
            if username:
                to_unblock[username] = note
                commands_found = True
        elif '---d' in line:
            # Delete user entirely
            username = extract_username_from_line(line)
            if username:
                to_delete.add(username)
                commands_found = True
        else:
            keep_plain.append(line)  # keep full line (could contain note)

    if not commands_found:
        return  # nothing to do

    # Load current users list
    users = load_user_list()
    updated_users = []
    modified_users = set()

    existing_usernames = [extract_username_from_line(u) for u in users]

    for user_line in users:
        uname = extract_username_from_line(user_line)
        if uname in to_unblock:
            # Remove block symbol if present and update note if provided
            base = user_line.lstrip(BLOCKED_SYMBOL).lstrip()
            # Remove old note
            base_without_note = remove_notes_from_line(base)
            new_note_raw = to_unblock.get(uname, '')
            # Clean any old block-date tags from whichever note we keep
            new_note = strip_block_dates(new_note_raw) if new_note_raw else ''

            clean_line = base_without_note
            if new_note:
                clean_line += f" #{new_note}"
            else:
                existing_note = extract_notes_from_line(base)
                cleaned_existing = strip_block_dates(existing_note)
                if cleaned_existing:
                    clean_line += f" #{cleaned_existing}"
            updated_users.append(clean_line)
            modified_users.add(uname)
            log_user_history(uname, "unblocked", "via blocked_users.txt")
        elif uname in to_delete:
            # Skip this line to delete user completely
            modified_users.add(uname)
            log_user_history(uname, "removed", "via blocked_users.txt")
            continue  # do not append to updated_users (removes from list)
        else:
            updated_users.append(user_line)

    # Move modified users to top for visibility
    final_users = updated_users.copy()
    for uname in modified_users:
        final_users = move_user_to_top(final_users, uname)

    # Persist changes
    save_user_state(final_users)  # update state snapshot
    backup_user_list()
    for uname in modified_users:
        backup_user(uname)
    save_user_list(final_users)

    # Re-write blocked_users.txt based on CURRENT state of user_list.txt
    # Only include users that are actually blocked (have 🚫 symbol)
    # Exclude users that were unblocked or deleted
    new_block_list = []
    
    # Rebuild blocked_users.txt from final user_list.txt state
    # (after processing unblocks/deletes and moving users to top)
    for user_line in final_users:
        if user_line.startswith(BLOCKED_SYMBOL):
            # This user is still blocked, add to blocked_users.txt
            entry = user_line.lstrip(BLOCKED_SYMBOL).lstrip()
            uname = extract_username_from_line(entry)
            # Only add if not in to_delete (shouldn't happen, but safety check)
            if uname not in to_delete:
                new_block_list.append(entry)
    
    # Write the updated blocked_users.txt
    with open(blocked_file, 'w', encoding='utf-8') as f:
        for entry in new_block_list:
            f.write(f"{entry}\n")

    # Remove subscription files for deleted users
    if to_delete:
        subscription_dir = 'subscriptions'
        for uname in to_delete:
            sub_file = os.path.join(subscription_dir, f"{uname}.txt")
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
            log_user_history(username, "expired", expiry_time.strftime("%Y-%m-%d %H:%M") if expiry_time else "")
            updated_line = f"{BLOCKED_SYMBOL}{user_line}"
            updated_users.append(updated_line)
        else:
            updated_users.append(user_line)
    if expired_users:
        # Move expired users to the top
        final_users = updated_users.copy()
        for username in expired_users:
            final_users = move_user_to_top(final_users, username)
        
        # Create a backup when users expire
        backup_user_list()
        save_user_list(final_users)
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
    # Extract just the usernames for comparison
    existing_usernames = [extract_username_from_line(user) for user in existing_users]
    
    # Debug print
    print(f"Discovering new subscriptions")
    print(f"Subscription files: {subscription_files}")
    print(f"Existing usernames: {existing_usernames}")
    
    for filename in subscription_files:
        base_username = filename[:-4]  # Remove .txt extension
        
        # Check if this username already exists in the user list
        if base_username not in existing_usernames:
            # Username doesn't exist, add it normally
            print(f"Adding new subscription: {base_username}")
            add_user_to_list(base_username)
        else:
            print(f"Subscription {base_username} already exists, skipping")
        # If the username already exists, we don't need to do anything
        # The add_user_to_list function handles generating unique usernames if needed

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
    """Extract normalized server config for duplicate detection.
    Supports: vless, vmess, trojan, ss, hysteria, hysteria2"""
    try:
        server_line = server_line.strip()
        if server_line.startswith('vmess://'):
            return normalize_vmess_url(server_line)
        elif server_line.startswith(('vless://', 'trojan://', 'ss://', 'hysteria://', 'hysteria2://')):
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
CONTROL_PANEL_FILE = 'control_panel.txt'
HISTORY_FILE = 'server_history.txt'
USER_HISTORY_FILE = 'user_history.txt'
QUARANTINE_DAYS = 3
USER_HISTORY_DAYS = 10  # Keep user history for 10 days
BACKUP_DAYS = 10  # Keep backups for 10 days
SERVER_HISTORY_DAYS = 10  # Keep server history for 10 days
# Timeout (seconds) for TCP health-check
VALIDATION_TIMEOUT = 3

# Fast-run flag: when set, the script skips heavy maintenance (health-checks, flag decoration, etc.)
FAST_RUN = os.getenv("FAST_RUN", "0") == "1"

def log_history(server, action):
    iran_time = get_iran_time()
    now = iran_time.strftime("%Y-%m-%d %H:%M")
    new_entry = f"{server} | {action} | {now}\n"
    existing_lines = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            existing_lines = f.readlines()
    
    # Filter entries older than SERVER_HISTORY_DAYS days
    if existing_lines:
        filtered_lines = []
        cutoff_date = iran_time - datetime.timedelta(days=SERVER_HISTORY_DAYS)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")
        
        for line in existing_lines:
            try:
                parts = line.strip().split(' | ')
                if len(parts) >= 3:
                    entry_date = parts[2].split()[0]  # Get just the date part
                    if entry_date >= cutoff_str:
                        filtered_lines.append(line)
            except:
                # Keep line if we can't parse the date
                filtered_lines.append(line)
                
        existing_lines = filtered_lines
        
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        # Write new entry first, followed by existing entries
        f.write(new_entry + ''.join(existing_lines))

def log_user_history(username, action, details="", max_days=USER_HISTORY_DAYS):
    """
    Log user-related actions with newest entries at the top
    Actions: added, removed, blocked, unblocked, renamed, expiry_set, expired
    """
    # If details starts with #, it's likely a note directly from user_data
    if details.startswith('#'):
        # Extract note content without the # prefix
        note_content = details[1:].strip()
        # Just use the formatted note
        details = f"[Note: {note_content}]"
    # Check if notes are already included in details in our standard format
    elif "[Note:" not in details:
        # Only lookup notes in user_list if not already in details
        notes = ""
        users = load_user_list()
        for line in users:
            if username == extract_username_from_line(line):
                line_notes = extract_notes_from_line(line)
                if line_notes:
                    notes = f"[Note: {line_notes}]"
                    break

        # Append notes to details if available
        if notes and details:
            details = f"{details} {notes}"
        elif notes:
            details = notes

    iran_time = get_iran_time()
    now = iran_time.strftime("%Y-%m-%d %H:%M")
    new_entry = f"{username} | {action} | {details} | {now}\n\n"
    
    # Read existing entries
    existing_lines = []
    if os.path.exists(USER_HISTORY_FILE):
        with open(USER_HISTORY_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
            # Split by double newlines (empty line between entries)
            entries = content.split('\n\n')
            # Filter out empty entries
            existing_lines = [entry + '\n\n' for entry in entries if entry.strip()]
    
    # Remove entries older than max_days
    if existing_lines:
        filtered_lines = []
        cutoff_date = iran_time - datetime.timedelta(days=max_days)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")
        
        for line in existing_lines:
            try:
                entry = line.strip()
                parts = entry.split(' | ')
                if len(parts) >= 4:
                    entry_date = parts[3].split()[0]  # Get just the date part
                    if entry_date >= cutoff_str:
                        filtered_lines.append(line)
            except:
                # Keep line if we can't parse the date
                filtered_lines.append(line)
                
        existing_lines = filtered_lines
    
    # Write the log with new entry at the top
    with open(USER_HISTORY_FILE, 'w', encoding='utf-8') as f:
        f.write(new_entry + ''.join(existing_lines).rstrip('\n') + '\n')

# === REMOVE DUPLICATES WITH LOGGING ===

def get_server_key(server):
    """Generate a unique key for a server based on core config (ignoring remark)."""
    try:
        if server.startswith('vmess://'):
            base64_str = server[8:].split('#')[0]
            base64_str += '=' * ((4 - len(base64_str) % 4) % 4)
            data = json.loads(base64.b64decode(base64_str).decode('utf-8'))
            return f"vmess:{data.get('add')}:{data.get('port')}:{data.get('id')}:{data.get('net')}:{data.get('path')}"
        elif '#' in server:
            return server.split('#')[0]
        return server
    except Exception:
        return server

def remove_duplicates(servers):
    """Remove duplicate servers while preserving order."""
    seen = set()
    unique_servers = []
    for s in servers:
        if not s.strip():
            continue
        key = get_server_key(s.strip())
        if key not in seen:
            seen.add(key)
            unique_servers.append(s.strip())
    return unique_servers

def remove_yaml_duplicates(yaml_data):
    """Remove duplicate proxies from YAML while preserving order and proxy-groups."""
    if not isinstance(yaml_data, dict) or 'proxies' not in yaml_data or not isinstance(yaml_data['proxies'], list):
        return yaml_data
    seen = set()
    unique_proxies = []
    for p in yaml_data['proxies']:
        if not isinstance(p, dict):
            continue
        key = (p.get('server'), p.get('port'), p.get('type'), p.get('uuid'), p.get('public-key'))
        if key not in seen:
            seen.add(key)
            unique_proxies.append(p)
    
    yaml_data['proxies'] = unique_proxies
    valid_names = {p.get('name') for p in unique_proxies if p.get('name')}
    if 'proxy-groups' in yaml_data and isinstance(yaml_data['proxy-groups'], list):
        for group in yaml_data['proxy-groups']:
            if isinstance(group, dict) and 'proxies' in group:
                group['proxies'] = [name for name in group['proxies'] if name in valid_names]
    return yaml_data

def parse_non_working_line(line):
    """Parse non_working.txt line. Supports two formats:
    Old format: server | date
    New format: server | source_file | date
    """
    try:
        parts = line.rsplit('|', 2)
        if len(parts) == 2:
            # Old format: server | date
            server = parts[0].strip()
            date_str = parts[1].strip()
            source_file = None  # Unknown source
        else:
            # New format: server | source_file | date
            server = parts[0].strip()
            source_file = parts[1].strip()
            date_str = parts[2].strip()
        
        dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M")
        return server, dt, source_file
    except Exception:
        return None, None, None

# === Control Panel Functions ===

def get_control_panel_settings():
    """Read control_panel.txt and return active settings:
    - active_server (e.g. servers.warp.txt)
    - flags_enabled (True/False)
    - auto_rename_enabled (True/False)
    - duplicates_enabled (True/False, default False)
    - max_servers ('ALL' or int)
    - expired_msg (string)
    - server_files (list of all server pool files)
    """
    default_servers = ['servers.warp.txt', 'servers.txt', 'servers1.txt', 'warp.yaml']
    default_expired_msg = "اشتراک شما تمام شده است لطفا اشتراک خود را تمدید کنید"
    default_max_servers = 'ALL'
    default_duplicates = False
    if not os.path.exists(CONTROL_PANEL_FILE):
        return {
            'active_server': MAIN_FILE,
            'flags_enabled': True,
            'auto_rename_enabled': True,
            'duplicates_enabled': default_duplicates,
            'max_servers': default_max_servers,
            'expired_msg': default_expired_msg,
            'server_files': default_servers
        }

    with open(CONTROL_PANEL_FILE, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]

    active_server = None
    flags_enabled = True
    auto_rename_enabled = True
    duplicates_enabled = default_duplicates
    max_servers = default_max_servers
    expired_msg = default_expired_msg
    found_server_files = []
    explicit_on_servers = []
    ticked_servers = []
    all_on_servers = []

    for line in lines:
        if line.startswith('#') or line.startswith('-'):
            continue
        line_clean = line.replace('✓', '').strip()
        
        # Check FLAGS setting
        if re.match(r'^(flags|flag)\b', line_clean, re.IGNORECASE):
            if any(off_word in line_clean.upper() for off_word in [': OFF', '= OFF', ' OFF', 'DISABLE', '---OFF']):
                flags_enabled = False
            elif any(on_word in line_clean.upper() for on_word in [': ON', '= ON', ' ON', 'ENABLE', '---ON']):
                flags_enabled = True
            continue

        # Check AUTO_RENAME setting
        if re.match(r'^(auto_rename|autorename|rename)\b', line_clean, re.IGNORECASE):
            if any(off_word in line_clean.upper() for off_word in [': OFF', '= OFF', ' OFF', 'DISABLE', '---OFF']):
                auto_rename_enabled = False
            elif any(on_word in line_clean.upper() for on_word in [': ON', '= ON', ' ON', 'ENABLE', '---ON']):
                auto_rename_enabled = True
            continue

        # Check DUPLICATES setting
        if re.match(r'^(duplicates|duplicate_checker|duplicate|dedup)\b', line_clean, re.IGNORECASE):
            if any(on_word in line_clean.upper() for on_word in [': ON', '= ON', ' ON', 'ENABLE', '---ON']):
                duplicates_enabled = True
            elif any(off_word in line_clean.upper() for off_word in [': OFF', '= OFF', ' OFF', 'DISABLE', '---OFF']):
                duplicates_enabled = False
            continue

        # Check MAX_SERVERS setting
        if re.match(r'^(max_servers|max_server|limit_servers|limit)\b', line_clean, re.IGNORECASE):
            if ':' in line_clean:
                val = line_clean.split(':', 1)[1].strip()
            elif '=' in line_clean:
                val = line_clean.split('=', 1)[1].strip()
            else:
                val = line_clean.split(maxsplit=1)[1].strip() if len(line_clean.split()) > 1 else ""
            if val:
                val_upper = val.upper()
                if val_upper in ['ALL', 'OFF', 'UNLIMITED', 'NONE', 'NO', '0']:
                    max_servers = 'ALL'
                else:
                    digits = re.findall(r'\d+', val)
                    if digits:
                        num = int(digits[0])
                        max_servers = num if num > 0 else 'ALL'
            continue

        # Check EXPIRED_MSG setting
        if re.match(r'^(expired_msg|expired_message|expired)\b', line_clean, re.IGNORECASE):
            if ':' in line_clean:
                msg_val = line_clean.split(':', 1)[1].strip()
            elif '=' in line_clean:
                msg_val = line_clean.split('=', 1)[1].strip()
            else:
                msg_val = line_clean.split(maxsplit=1)[1].strip() if len(line_clean.split()) > 1 else ""
            if msg_val:
                expired_msg = msg_val
            continue

        # Server line
        filename_part = line_clean.split(':')[0].split('=')[0].split()[0] if line_clean else ''
        if filename_part and ('.' in filename_part or os.path.exists(filename_part) or is_external_source(filename_part)):
            # Check for delete command
            if '---d' in line.lower() or '---del' in line.lower() or '---delete' in line.lower():
                continue

            if filename_part not in found_server_files:
                found_server_files.append(filename_part)
            
            has_tick = '✓' in line
            has_on = '---on' in line.lower() or any(on_word in line.upper() for on_word in [': ON', '= ON', ' ON', ':ON', '=ON'])
            has_off = any(off_word in line.upper() for off_word in [': OFF', '= OFF', ' OFF', ':OFF', '=OFF'])

            if has_tick:
                ticked_servers.append(filename_part)
            
            if has_on and not has_off:
                all_on_servers.append(filename_part)
                if not has_tick or '---on' in line.lower():
                    explicit_on_servers.append(filename_part)

    if not found_server_files:
        found_server_files = [s for s in default_servers if os.path.exists(s)] or default_servers

    # Smart selection priority:
    # 1. Server explicitly newly set to ON / ---on (without having tick originally or with ---on)
    if explicit_on_servers:
        active_server = explicit_on_servers[-1]
    # 2. Server with tick ✓
    elif ticked_servers:
        active_server = ticked_servers[0]
    # 3. Any server with ON
    elif all_on_servers:
        active_server = all_on_servers[0]
    else:
        active_server = found_server_files[0]

    return {
        'active_server': active_server,
        'flags_enabled': flags_enabled,
        'auto_rename_enabled': auto_rename_enabled,
        'duplicates_enabled': duplicates_enabled,
        'max_servers': max_servers,
        'expired_msg': expired_msg,
        'server_files': found_server_files
    }

def get_active_server_file():
    """Read control_panel.txt and return the active server file name."""
    settings = get_control_panel_settings()
    return settings['active_server']

def process_control_panel():
    """Process control_panel.txt to handle ON/OFF and ---on commands, enforcing the unified layout:
    # === SERVER POOL ===
    ✓ servers.warp.txt: ON
    servers.txt: OFF
    servers1.txt: OFF
    warp.yaml: OFF
    --------------------------------
    # === SETTINGS ===
    ✓ FLAGS: ON
    ✓ AUTO_RENAME: ON
    DUPLICATES: OFF
    MAX_SERVERS: ALL
    EXPIRED_MSG: اشتراک شما تمام شده است لطفا اشتراک خود را تمدید کنید
    --------------------------------
    """
    settings = get_control_panel_settings()
    active_server = settings['active_server']
    flags_enabled = settings['flags_enabled']
    auto_rename_enabled = settings['auto_rename_enabled']
    duplicates_enabled = settings['duplicates_enabled']
    max_servers = settings['max_servers']
    expired_msg = settings['expired_msg']
    server_files = settings['server_files']

    output_lines = [
        "# === SERVER POOL ==="
    ]
    for sfile in server_files:
        if sfile == active_server:
            output_lines.append(f"✓ {sfile}: ON")
        else:
            output_lines.append(f"{sfile}: OFF")
    
    output_lines.append("--------------------------------")
    output_lines.append("# === SETTINGS ===")
    if flags_enabled:
        output_lines.append("✓ FLAGS: ON")
    else:
        output_lines.append("FLAGS: OFF")

    if auto_rename_enabled:
        output_lines.append("✓ AUTO_RENAME: ON")
    else:
        output_lines.append("AUTO_RENAME: OFF")

    if duplicates_enabled:
        output_lines.append("✓ DUPLICATES: ON")
    else:
        output_lines.append("DUPLICATES: OFF")
    
    output_lines.append(f"MAX_SERVERS: {max_servers}")
    output_lines.append(f"EXPIRED_MSG: {expired_msg}")
    output_lines.append("--------------------------------")

    new_content = "\n".join(output_lines) + "\n"
    
    current_content = ""
    if os.path.exists(CONTROL_PANEL_FILE):
        with open(CONTROL_PANEL_FILE, 'r', encoding='utf-8') as f:
            current_content = f.read()

    if new_content.strip() != current_content.strip():
        with open(CONTROL_PANEL_FILE, 'w', encoding='utf-8') as f:
            f.write(new_content)
        try:
            flag_str = "ON" if flags_enabled else "OFF"
            rename_str = "ON" if auto_rename_enabled else "OFF"
            dup_str = "ON" if duplicates_enabled else "OFF"
            print(f"✓ Control panel updated: Active = {active_server}, FLAGS = {flag_str}, AUTO_RENAME = {rename_str}, DUPLICATES = {dup_str}, MAX_SERVERS = {max_servers}")
        except UnicodeEncodeError:
            print(f"Control panel updated: Active = {active_server}, FLAGS = {flags_enabled}, AUTO_RENAME = {auto_rename_enabled}, DUPLICATES = {duplicates_enabled}, MAX_SERVERS = {max_servers}")

def load_main_servers():
    """Load servers from the active server file specified in control_panel.txt."""
    active_file = get_active_server_file()
    
    if is_external_source(active_file):
        content, is_yaml = load_external_source(active_file)
        if is_yaml and isinstance(content, dict):
            count = len(content.get('proxies', [])) if isinstance(content.get('proxies'), list) else 0
            try:
                print(f"📡 Loading external YAML config from: {active_file} ({count} proxies)")
            except UnicodeEncodeError:
                print(f"Loading external YAML config from: {active_file} ({count} proxies)")
            return content
        else:
            servers = content if isinstance(content, list) else []
            try:
                print(f"📡 Loading external servers from: {active_file} ({len(servers)} servers)")
            except UnicodeEncodeError:
                print(f"Loading external servers from: {active_file} ({len(servers)} servers)")
            return servers

    if not os.path.exists(active_file):
        if os.path.exists(f"{active_file}.txt"):
            active_file = f"{active_file}.txt"
        elif active_file.endswith('.txt') and os.path.exists(active_file[:-4]):
            active_file = active_file[:-4]
        else:
            print(f"⚠️ Active server file {active_file} not found, using default {MAIN_FILE}")
            active_file = MAIN_FILE
    
    if not os.path.exists(active_file):
        return {} if is_yaml_file(active_file) else []
    
    if is_yaml_file(active_file):
        try:
            with open(active_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                data = {}
            count = len(data.get('proxies', [])) if isinstance(data.get('proxies'), list) else 0
            try:
                print(f"📡 Loading YAML config from: {active_file} ({count} proxies)")
            except UnicodeEncodeError:
                print(f"Loading YAML config from: {active_file} ({count} proxies)")
            return data
        except Exception as e:
            print(f"⚠️ Error reading YAML from {active_file}: {e}")
            return {}
    else:
        with open(active_file, 'r', encoding='utf-8') as f:
            servers = [line.strip() for line in f if line.strip()]
        try:
            print(f"📡 Loading servers from: {active_file} ({len(servers)} servers)")
        except UnicodeEncodeError:
            print(f"Loading servers from: {active_file} ({len(servers)} servers)")
        return servers

def save_main_servers(servers):
    """Save servers to the active server file specified in control_panel.txt."""
    active_file = get_active_server_file()
    if is_external_source(active_file):
        return  # Preserve external URLs in .src.txt without overwriting with proxy strings
    if is_yaml_file(active_file):
        with open(active_file, 'w', encoding='utf-8') as f:
            yaml.dump(servers, f, sort_keys=False, allow_unicode=True)
    else:
        with open(active_file, 'w', encoding='utf-8') as f:
            if isinstance(servers, list):
                f.write('\n'.join(servers) + '\n')
            else:
                f.write(str(servers))

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
        server, dt, source_file = parse_non_working_line(line)
        if not server or not dt:
            keep_non_working.append(line)
            continue
        days_in_quarantine = (today.replace(tzinfo=None) - dt).days
        if days_in_quarantine >= QUARANTINE_DAYS:
            source_info = f"(from:{source_file})" if source_file else ""
            log_history(server, f"removed_after_3_days{source_info}")
        else:
            keep_non_working.append(line)
    save_non_working(keep_non_working)

def move_server_to_non_working(server_line):
    """Move a server to non_working.txt and track which server file it came from."""
    iran_time = get_iran_time()
    now_str = iran_time.strftime("%Y-%m-%d %H:%M")
    # Track source file: format: server | source_file | date
    source_file = get_active_server_file()
    entry = f"{server_line} | {source_file} | {now_str}"
    non_working = load_non_working()
    # Check if server already exists (comparing server part only)
    server_part = entry.split(' | ')[0]
    if not any(server_part in line.split(' | ')[0] for line in non_working):
        # Add new non-working servers to the top of the list
        non_working.insert(0, entry)
        save_non_working(non_working)
        log_history(server_line, f"moved_to_non_working(from:{source_file})")

def move_server_to_main(server_line, target_file=None):
    """Move a server back to a server file. If target_file is None, uses currently active file."""
    if target_file is None:
        target_file = get_active_server_file()
    
    # Load servers from target file
    if not os.path.exists(target_file):
        return
    
    with open(target_file, 'r', encoding='utf-8') as f:
        main_servers = [line.strip() for line in f if line.strip()]
    
    # Check for duplicates
    normalized_new = extract_server_config(server_line)
    for existing in main_servers:
        if extract_server_config(existing) == normalized_new:
            return
    
    main_servers.append(server_line)
    with open(target_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(main_servers) + '\n')
    log_history(server_line, f"moved_to_main({target_file})")

def process_non_working_recovery():
    """Recover servers from non_working.txt back to their original server files."""
    non_working_lines = load_non_working()
    keep_non_working = []
    for line in non_working_lines:
        server, dt, source_file = parse_non_working_line(line)
        if not server or not dt:
            keep_non_working.append(line)
            continue
        
        # Test if server is working again
        if validate_server(server):
            # Recover to original source file - each server goes back to where it came from
            # Example: server from servers1.txt goes back to servers1.txt, not servers.txt
            target_file = source_file if source_file and os.path.exists(source_file) else None
            move_server_to_main(server, target_file)
            source_info = f"from:{source_file}," if source_file else ""
            log_history(server, f"recovered_to_main({source_info}to:{target_file or 'active'})")
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
    """Validate server connectivity by testing TCP connection.
    Supports: vless, vmess, trojan, ss, hysteria, hysteria2"""
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
        elif server_line.startswith(('hysteria://', 'hysteria2://')):
            url_part = server_line.split('#')[0]
            parsed = urlparse(url_part)
            hostname = parsed.hostname
            port = parsed.port or 443
        if hostname and port:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(VALIDATION_TIMEOUT)
            result = sock.connect_ex((hostname, port))
            sock.close()
            return result == 0
    except Exception:
        return False
    return False

def get_blocked_users():
    """Return a set of usernames that are currently blocked."""
    blocked_set, _ = get_blocked_users_and_messages()
    return blocked_set

def get_blocked_users_and_messages():
    """Return:
    - blocked_users: set of usernames that are currently blocked.
    - user_messages: dict mapping username -> custom_message (if any specified via | msg: or ---msg)
    """
    blocked_users = set()
    user_messages = {}

    if os.path.exists('blocked_users.txt'):
        try:
            with open('blocked_users.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    username = extract_username_from_line(line)
                    if username:
                        blocked_users.add(username)
                        msg = extract_custom_message_from_line(line)
                        if msg:
                            user_messages[username] = msg
        except FileNotFoundError:
            pass

    if os.path.exists(USER_LIST_FILE):
        try:
            with open(USER_LIST_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    username = extract_username_from_line(line)
                    if username:
                        if line.startswith(BLOCKED_SYMBOL) or '---b' in line:
                            blocked_users.add(username)
                        msg = extract_custom_message_from_line(line)
                        if msg:
                            user_messages[username] = msg
        except FileNotFoundError:
            pass

    return blocked_users, user_messages

def should_block_user(username, blocked_users):
    return username in blocked_users

def get_fake_servers(expired_msg=None):
    fake_remark = expired_msg.strip() if expired_msg and expired_msg.strip() else "اشتراک شما تمام شده است لطفا اشتراک خود را تمدید کنید"
    return [
        f"vless://12345678-1234-1234-1234-123456789abc@127.0.0.1:443?encryption=none&security=tls&type=ws&path=%2F#{fake_remark}"
    ]

def distribute_servers(servers, username):
    return servers

# === User List Backup Functions ===

def backup_user_list():
    """Create a dated backup of user_list.txt in a backups folder"""
    if not os.path.exists(USER_LIST_FILE):
        return False
    
    # Create backups directory if it doesn't exist
    backup_dir = Path('backups')
    backup_dir.mkdir(exist_ok=True)
    
    # Generate backup filename with timestamp
    iran_time = get_iran_time()
    # Use date format that sorts in reverse chronological order
    # Higher numbers will appear first in directory listing
    timestamp = f"{9999 - iran_time.year:04d}-{12 - iran_time.month:02d}-{31 - iran_time.day:02d}_{23 - iran_time.hour:02d}-{59 - iran_time.minute:02d}-{59 - iran_time.second:02d}"
    # Also include human-readable date in the filename
    display_timestamp = iran_time.strftime("%Y-%m-%d_%H-%M-%S")
    backup_filename = backup_dir / f"user_list_{timestamp}_{display_timestamp}.txt"
    
    try:
        # Copy the user list to the backup file
        shutil.copy2(USER_LIST_FILE, backup_filename)
        
        # Cleanup old backups (keep those from last BACKUP_DAYS days)
        backups = list(backup_dir.glob("user_list_*.txt"))
        cutoff_date = iran_time - datetime.timedelta(days=BACKUP_DAYS)
        
        for backup_file in backups:
            # Extract date from filename
            try:
                # Check if it's our new format with both timestamps
                if "_20" in backup_file.name:  # Look for original timestamp portion
                    # Extract the original timestamp part (after the reverse timestamp)
                    filename_parts = backup_file.name.split('_')
                    if len(filename_parts) >= 4:  # Should be user_list_REVTS1_REVTS2_ORIGTS1_ORIGTS2.txt
                        # Try to find the original timestamp part
                        for i, part in enumerate(filename_parts):
                            if part.startswith('20'):  # Year starting with 20xx
                                orig_date_str = part  # This should be the year
                                if len(filename_parts) > i+1:
                                    orig_date_str = f"{orig_date_str}-{filename_parts[i+1]}"  # Add month-day
                                    file_date = datetime.datetime.strptime(orig_date_str, "%Y-%m-%d").replace(tzinfo=IRAN_TZ)
                                    if file_date < cutoff_date:
                                        backup_file.unlink()
                                break
                else:
                    # Legacy format is user_list_YYYY-MM-DD_HH-MM-SS.txt
                    date_str = backup_file.stem.split('_', 1)[1]  # Get YYYY-MM-DD_HH-MM-SS part
                    date_parts = date_str.split('_')
                    if len(date_parts) >= 2:
                        date_str = date_parts[0]  # Get YYYY-MM-DD part
                        file_date = datetime.datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=IRAN_TZ)
                        if file_date < cutoff_date:
                            # File is older than BACKUP_DAYS days
                            backup_file.unlink()
            except (ValueError, IndexError):
                # Skip files with invalid naming format
                continue
                
        return True
    except Exception as e:
        print(f"⚠️ Backup failed: {str(e)}")
        return False

def backup_user(username):
    """Create a backup of a specific user's entry"""
    if not os.path.exists(USER_LIST_FILE):
        return False
    
    # Load the current user list
    users = load_user_list()
    
    # Find the user's entry
    user_entry = None
    for line in users:
        if extract_username_from_line(line) == username:
            user_entry = line
            break
    
    if not user_entry:
        return False
    
    # Create user backups directory if it doesn't exist
    user_backup_dir = Path('backups/users')
    user_backup_dir.mkdir(exist_ok=True, parents=True)
    
    # Create user-specific directory
    user_dir = user_backup_dir / username
    user_dir.mkdir(exist_ok=True)
    
    # Generate backup filename with timestamp
    iran_time = get_iran_time()
    # Use date format that sorts in reverse chronological order
    timestamp = f"{9999 - iran_time.year:04d}-{12 - iran_time.month:02d}-{31 - iran_time.day:02d}_{23 - iran_time.hour:02d}-{59 - iran_time.minute:02d}"
    # Also include human-readable date in filename
    display_timestamp = iran_time.strftime("%Y-%m-%d_%H-%M")
    backup_filename = user_dir / f"{username}_{timestamp}_{display_timestamp}.txt"
    
    try:
        # Write the user entry to the backup file
        with open(backup_filename, 'w', encoding='utf-8') as f:
            f.write(user_entry)
        
        # Cleanup old backups (keep those from last BACKUP_DAYS days)
        backups = list(user_dir.glob(f"{username}_*.txt"))
        cutoff_date = iran_time - datetime.timedelta(days=BACKUP_DAYS)
        
        for backup_file in backups:
            # Extract date from filename (format: username_TIMESTAMP_DISPLAYTIMESTAMP.txt)
            # Example: username_7980-12-31_23-59_2024-01-01_12-30.txt
            # display_timestamp is the last two parts: YYYY-MM-DD_HH-MM
            try:
                filename = backup_file.stem  # Get filename without extension
                parts = filename.split('_')
                if len(parts) >= 5:
                    # Display timestamp is the last two parts: YYYY-MM-DD_HH-MM
                    # Extract date part (second to last): YYYY-MM-DD
                    date_str = parts[-2]  # YYYY-MM-DD
                    file_date = datetime.datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=IRAN_TZ)
                    if file_date < cutoff_date:
                        # File is older than BACKUP_DAYS days
                        backup_file.unlink()
            except (ValueError, IndexError):
                # Skip files with invalid naming format
                continue
                
        return True
    except Exception as e:
        print(f"⚠️ User backup failed for {username}: {str(e)}")
        return False

def update_all_subscriptions():
    """Main entry-point. Behaviour depends on FAST_RUN flag."""

    # Process control panel first to determine which server file is active
    process_control_panel()
    settings = get_control_panel_settings()
    active_file = settings['active_server']
    flags_enabled = settings['flags_enabled']
    auto_rename_enabled = settings['auto_rename_enabled']
    duplicates_enabled = settings['duplicates_enabled']
    max_servers = settings['max_servers']
    expired_msg = settings['expired_msg']

    # Always make a backup of user_list before starting
    if os.path.exists(USER_LIST_FILE):
        backup_user_list()
        # Detect any manual changes since last run
        detect_manual_changes()

    # Process any commands written directly inside blocked_users.txt FIRST
    # This must run before process_user_commands() because process_user_commands()
    # rebuilds blocked_users.txt, which would remove the ---ub/---d commands
    process_blocked_users_commands()
    # Then process user commands & expiry – they are lightweight
    process_user_commands()
    check_expired_users()

    if not FAST_RUN:
        # Heavy maintenance tasks (hourly / scheduled)
        discover_new_subscriptions()
        
        active_content = load_main_servers()
        if is_external_source(active_file):
            active_is_yaml = isinstance(active_content, dict)
        else:
            active_is_yaml = is_yaml_file(active_file)

        if active_is_yaml:
            yaml_config = active_content
            if duplicates_enabled:
                yaml_config = remove_yaml_duplicates(yaml_config)
            updated_yaml = update_yaml_remarks(yaml_config, flags_enabled=flags_enabled, auto_rename_enabled=auto_rename_enabled)
            save_main_servers(updated_yaml)
            active_content = updated_yaml
        else:
            current_servers = active_content if isinstance(active_content, list) else []
            valid_servers = remove_duplicates(current_servers) if duplicates_enabled else current_servers

            # Update remarks
            all_servers = update_server_remarks(valid_servers, flags_enabled=flags_enabled, auto_rename_enabled=auto_rename_enabled)
            save_main_servers(all_servers)
            active_content = all_servers
    else:
        # FAST_RUN → skip all heavy work, use current list as-is
        active_content = load_main_servers()
        if is_external_source(active_file):
            active_is_yaml = isinstance(active_content, dict)
        else:
            active_is_yaml = is_yaml_file(active_file)

    # Build / update subscription files for every user
    blocked_users, user_messages = get_blocked_users_and_messages()
    subscription_dir = 'subscriptions'
    if not os.path.exists(subscription_dir):
        os.makedirs(subscription_dir)
    
    # Load user list to identify which subscriptions are managed by automation
    managed_users = load_user_list()
    managed_usernames = {extract_username_from_line(user) for user in managed_users}

    # Map username -> custom source file if specified (e.g. servers1.txt, warp.yaml, external.src.txt, https://...)
    user_custom_sources = {}
    for user_line in managed_users:
        uname = extract_username_from_line(user_line)
        src = extract_custom_source_from_line(user_line)
        if src and (os.path.exists(src) or is_external_source(src)):
            user_custom_sources[uname] = src

    # Pool content cache: source_file -> (content, is_yaml)
    pool_cache = {
        active_file: (active_content, active_is_yaml)
    }

    def get_pool_content(src_file):
        if src_file in pool_cache:
            return pool_cache[src_file]
        
        if is_external_source(src_file):
            try:
                content, is_yaml = load_external_source(src_file)
                if is_yaml and isinstance(content, dict):
                    if not FAST_RUN:
                        if duplicates_enabled:
                            content = remove_yaml_duplicates(content)
                        content = update_yaml_remarks(content, flags_enabled=flags_enabled, auto_rename_enabled=auto_rename_enabled)
                    pool_cache[src_file] = (content, True)
                    return content, True
                else:
                    servers = content if isinstance(content, list) else []
                    if not FAST_RUN:
                        if duplicates_enabled:
                            servers = remove_duplicates(servers)
                        servers = update_server_remarks(servers, flags_enabled=flags_enabled, auto_rename_enabled=auto_rename_enabled)
                    pool_cache[src_file] = (servers, False)
                    return servers, False
            except Exception as e:
                print(f"⚠️ Error loading external source {src_file}: {e}")
                return active_content, active_is_yaml

        actual_file = src_file
        if not os.path.exists(actual_file):
            if os.path.exists(f"{actual_file}.txt"):
                actual_file = f"{actual_file}.txt"
            elif actual_file.endswith('.txt') and os.path.exists(actual_file[:-4]):
                actual_file = actual_file[:-4]

        is_yaml = is_yaml_file(actual_file)
        if is_yaml:
            try:
                with open(actual_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                if not isinstance(data, dict):
                    data = {}
                if not FAST_RUN:
                    if duplicates_enabled:
                        data = remove_yaml_duplicates(data)
                    data = update_yaml_remarks(data, flags_enabled=flags_enabled, auto_rename_enabled=auto_rename_enabled)
                    with open(actual_file, 'w', encoding='utf-8') as f:
                        yaml.dump(data, f, sort_keys=False, allow_unicode=True)
                pool_cache[src_file] = (data, True)
                return data, True
            except Exception as e:
                print(f"⚠️ Error loading custom YAML {actual_file}: {e}")
                return active_content, active_is_yaml
        else:
            try:
                with open(actual_file, 'r', encoding='utf-8') as f:
                    servers = [line.strip() for line in f if line.strip()]
                if not FAST_RUN:
                    if duplicates_enabled:
                        servers = remove_duplicates(servers)
                    servers = update_server_remarks(servers, flags_enabled=flags_enabled, auto_rename_enabled=auto_rename_enabled)
                    with open(actual_file, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(servers) + '\n')
                pool_cache[src_file] = (servers, False)
                return servers, False
            except Exception as e:
                print(f"⚠️ Error loading custom source {actual_file}: {e}")
                return active_content, active_is_yaml
    
    # First, ensure subscription files exist for all managed users
    for user_line in managed_users:
        username = extract_username_from_line(user_line)
        subscription_path = os.path.join(subscription_dir, f"{username}.txt")
        if not os.path.exists(subscription_path):
            # Create empty subscription file if it doesn't exist
            with open(subscription_path, 'w', encoding='utf-8') as f:
                f.write('')
            try:
                print(f"Created missing subscription file: {username}.txt")
            except UnicodeEncodeError:
                print(f"[OK] Created missing subscription file: {username}.txt")
    
    subscription_files = [f for f in os.listdir(subscription_dir) if f.endswith('.txt')]
    for filename in subscription_files:
        username = filename[:-4]
        
        # Only update subscriptions for users in user_list.txt (managed users)
        # Manual subscriptions (users not in user_list.txt) will be preserved
        if username not in managed_usernames:
            try:
                print(f"Preserving manual subscription: {username}.txt (user not in user_list.txt)")
            except UnicodeEncodeError:
                print(f"Preserving manual subscription: {username}.txt (user not in user_list.txt)")
            continue
        
        is_blocked = should_block_user(username, blocked_users)
        subscription_path = os.path.join(subscription_dir, filename)

        # Per-user custom message
        has_custom_msg = username in user_messages and bool(user_messages[username])
        custom_msg_text = user_messages.get(username, "").strip()

        # For blocked users: use per-user message if present, otherwise global EXPIRED_MSG
        blocked_msg = custom_msg_text if has_custom_msg else expired_msg

        # Check if user has a custom source file assigned
        user_src_file = user_custom_sources.get(username, active_file)
        user_content, user_is_yaml = get_pool_content(user_src_file)

        if user_is_yaml:
            if is_blocked:
                # Blocked user: deliver ONLY 1 fake proxy with the blocked notice
                fake_yaml = get_fake_yaml_config(blocked_msg)
                yaml_str = yaml.dump(fake_yaml, sort_keys=False, allow_unicode=True)
            else:
                # Active user: deliver working proxies
                final_yaml = user_content
                if max_servers != 'ALL' and isinstance(max_servers, int) and max_servers > 0 and isinstance(user_content, dict):
                    final_yaml = dict(user_content)
                    proxies_list = user_content.get('proxies', [])
                    sliced_proxies = proxies_list[:max_servers]
                    final_yaml['proxies'] = sliced_proxies
                    
                    # Synchronize proxy names in proxy-groups
                    valid_names = [p.get('name') for p in sliced_proxies if isinstance(p, dict) and p.get('name')]
                    if 'proxy-groups' in final_yaml and isinstance(final_yaml['proxy-groups'], list):
                        new_groups = []
                        for group in final_yaml['proxy-groups']:
                            if isinstance(group, dict):
                                g_copy = dict(group)
                                g_proxies = group.get('proxies', [])
                                g_copy['proxies'] = [p for p in g_proxies if p in valid_names]
                                new_groups.append(g_copy)
                            else:
                                new_groups.append(group)
                        final_yaml['proxy-groups'] = new_groups

                # Active user with custom message: inject banner fake proxy at top (index 0)
                if has_custom_msg and isinstance(final_yaml, dict):
                    final_yaml = dict(final_yaml)
                    banner_proxy = {
                        "name": custom_msg_text,
                        "type": "vless",
                        "server": "127.0.0.1",
                        "port": 443,
                        "uuid": "12345678-1234-1234-1234-123456789abc",
                        "cipher": "auto",
                        "udp": False,
                        "tls": False
                    }
                    existing_proxies = list(final_yaml.get('proxies', []))
                    final_yaml['proxies'] = [banner_proxy] + existing_proxies

                yaml_str = yaml.dump(final_yaml, sort_keys=False, allow_unicode=True)
            with open(subscription_path, 'w', encoding='utf-8') as f:
                f.write(yaml_str)
        else:
            if is_blocked:
                # Blocked user: deliver ONLY 1 fake server with the blocked notice
                servers_for_user = get_fake_servers(blocked_msg)
            else:
                # Active user: deliver working servers
                servers_for_user = list(user_content) if isinstance(user_content, list) else []
                if max_servers != 'ALL' and isinstance(max_servers, int) and max_servers > 0:
                    servers_for_user = servers_for_user[:max_servers]
                
                # Active user with custom message: inject banner fake server at top (index 0)
                if has_custom_msg:
                    banner_server = f"vless://12345678-1234-1234-1234-123456789abc@127.0.0.1:443?encryption=none&security=tls&type=ws&path=%2F#{custom_msg_text}"
                    servers_for_user = [banner_server] + servers_for_user

            with open(subscription_path, 'w', encoding='utf-8') as f:
                subscription_content = '\n'.join(servers_for_user)
                encoded_content = base64.b64encode(subscription_content.encode('utf-8')).decode('utf-8')
                f.write(encoded_content)

if __name__ == "__main__":
    update_all_subscriptions()
