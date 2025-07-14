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

# Cache for IP to country code lookups
IP_COUNTRY_CACHE = {}

def get_country_code(ip):
    if not ip:
        return ''
    
    # Check cache first
    if ip in IP_COUNTRY_CACHE:
        return IP_COUNTRY_CACHE[ip]
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode,status,message", timeout=5)
        if response.status_code == 200:
            data = response.json()
            
            # Check if the API returned an error
            if data.get('status') == 'fail':
                print(f"IP API error for {ip}: {data.get('message', 'Unknown error')}")
                IP_COUNTRY_CACHE[ip] = ''
                return ''
                
            cc = data.get('countryCode', '')
            if cc and len(cc) == 2:
                # Store in cache
                IP_COUNTRY_CACHE[ip] = cc.upper()
                return cc.upper()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching country code for IP {ip}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error processing IP {ip}: {str(e)}")
    
    # Cache failed lookups too
    IP_COUNTRY_CACHE[ip] = ''
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
    # Process in batches of 40 to respect API rate limits
    batch_size = 40
    
    for batch_idx in range(0, len(servers), batch_size):
        batch_end = min(batch_idx + batch_size, len(servers))
        batch = servers[batch_idx:batch_end]
        
        # Process this batch
        for idx, server in enumerate(batch, batch_idx + 1):
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
            time.sleep(0.1)  # Small delay between API calls
        
        # If we have more batches to process, wait to avoid rate limits
        if batch_end < len(servers):
            print(f"Processed {batch_end}/{len(servers)} servers. Waiting to avoid rate limits...")
            time.sleep(65)  # Wait 65 seconds between batches to reset API rate limit
    
    return updated_servers

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
        if any(cmd in line for cmd in ['---b', '---ub', '---d', '---m', '---r', '---es']):
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
        notes = extract_notes_from_line(user_line)
        details = f"Line: {user_line}"
        if notes:
            details = f"Line: {user_line} [Note: {notes}]"
        log_user_history(username, "manual_add", details)
        manual_modified_users.add(username)
    
    # Find modified users (same username but different line content)
    modified = False
    for username in last_usernames.intersection(current_usernames):
        if last_lines[username] != current_lines.get(username, ''):
            modified = True  # Users were manually modified
            # Use difflib to find exact changes
            differ = Differ()
            diff = list(differ.compare([last_lines[username]], [current_lines[username]]))
            diff_text = '\n'.join(diff)
            notes = extract_notes_from_line(current_lines[username])
            details = f"Changes:\n{diff_text}"
            if notes:
                details = f"Changes:\n{diff_text} [Note: {notes}]"
            log_user_history(username, "manual_change", details)
            manual_modified_users.add(username)
    
    # If any manual changes were detected, create a full backup
    if any_manual_changes or modified:
        backup_user_list()
        
    # Backup all manually modified users
    for username in manual_modified_users:
        backup_user(username)
    
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

def is_blocked_user(user_line):
    return user_line.startswith(BLOCKED_SYMBOL)

def organize_user_list(users):
    """
    Organize the user list with:
    1. All newly changed users (unblocked, renamed, modified) at the top of active users section
    2. Regular unblocked users below changed users
    3. All blocked users below active users
    4. Newly blocked users at the top of the blocked section
    5. Regular blocked users at the bottom
    """
    # Split users into blocked and unblocked
    blocked_users = []
    unblocked_users = []
    
    # First, identify newly blocked or modified users
    newly_blocked = []
    newly_modified = []
    newly_unblocked = []
    renamed_users = []
    regular_blocked = []
    regular_unblocked = []
    
    for user_line in users:
        # Check if this is a newly blocked user (contains ---b command)
        if '---b' in user_line:
            username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            
            # Create the new blocked user line without the command
            if user_data and notes:
                updated_line = f"{BLOCKED_SYMBOL}{username} {user_data} #{notes}"
            elif user_data:
                updated_line = f"{BLOCKED_SYMBOL}{username} {user_data}"
            elif notes:
                updated_line = f"{BLOCKED_SYMBOL}{username} #{notes}"
            else:
                updated_line = f"{BLOCKED_SYMBOL}{username}"
                
            newly_blocked.append(updated_line)
        
        # Check if this is a newly unblocked user (contains ---ub command)
        elif '---ub' in user_line:
            username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            
            # Create the new unblocked user line without the command
            if user_data and notes:
                updated_line = f"{username} {user_data} #{notes}"
            elif user_data:
                updated_line = f"{username} {user_data}"
            elif notes:
                updated_line = f"{username} #{notes}"
            else:
                updated_line = username
                
            newly_unblocked.append(updated_line)
        
        # Check if this is a newly modified user (contains ---r or ---es command)
        elif '---r' in user_line or '---es' in user_line:
            # Process rename command
            if '---r' in user_line:
                old_username = extract_username_from_line(user_line)
                user_data = extract_user_data_from_line(user_line)
                notes = extract_notes_from_line(user_line)
                command_part = user_line.split('---r')[1]
                if '#' in command_part:
                    command_part = command_part.split('#')[0]
                new_username = command_part.strip().split()[0] if command_part.strip() else ''
                
                if new_username and new_username != old_username:
                    symbol = BLOCKED_SYMBOL if user_line.startswith(BLOCKED_SYMBOL) else ''
                    if user_data and notes:
                        updated_line = f"{symbol}{new_username} {user_data} #{notes}"
                    elif user_data:
                        updated_line = f"{symbol}{new_username} {user_data}"
                    elif notes:
                        updated_line = f"{symbol}{new_username} #{notes}"
                    else:
                        updated_line = f"{symbol}{new_username}"
                    
                    if symbol:
                        newly_blocked.append(updated_line)
                    else:
                        renamed_users.append(updated_line)
                else:
                    # If rename failed, keep original line
                    if is_blocked_user(user_line):
                        regular_blocked.append(user_line)
                    else:
                        regular_unblocked.append(user_line)
            
            # Process expiry set command
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
                        
                        if symbol:
                            newly_blocked.append(updated_line)
                        else:
                            newly_modified.append(updated_line)
                    else:
                        # If expiry parsing failed, keep original line
                        if is_blocked_user(user_line):
                            regular_blocked.append(user_line)
                        else:
                            regular_unblocked.append(user_line)
                else:
                    # If command parsing failed, keep original line
                    if is_blocked_user(user_line):
                        regular_blocked.append(user_line)
                    else:
                        regular_unblocked.append(user_line)
        
        # For newly added users (contains ---m command)
        elif '---m' in user_line:
            username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            
            if user_data and notes:
                updated_line = f"{username} {user_data} #{notes}"
            elif user_data:
                updated_line = f"{username} {user_data}"
            elif notes:
                updated_line = f"{username} #{notes}"
            else:
                updated_line = username
                
            newly_modified.append(updated_line)
        
        # Regular users (no commands)
        else:
            if is_blocked_user(user_line):
                regular_blocked.append(user_line)
            else:
                regular_unblocked.append(user_line)
    
    # Combine the lists in the desired order
    # 1. All newly changed users (unblocked, renamed, modified) at the top of active users
    # 2. Regular unblocked users
    # 3. All blocked users below active users, with newly blocked at the top of blocked section
    # 4. Regular blocked users at the bottom
    newly_changed_users = newly_unblocked + renamed_users + newly_modified
    active_users = newly_changed_users + regular_unblocked
    blocked_users = newly_blocked + regular_blocked
    organized_users = active_users + blocked_users
    
    # Filter out users that should be deleted (---d command)
    final_users = [user for user in organized_users if not any(cmd in user for cmd in ['---d', '---b', '---ub', '---r', '---es', '---m'])]
    
    return final_users

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
        # Create a full backup when adding a new user
        backup_user_list()
        save_user_list(users)
        # Create individual backup for this new user
        backup_user(username)
        print(f"📝 Added new user: {new_entry}")
        notes = extract_notes_from_line(new_entry)
        details = user_data
        if notes:
            details = f"{user_data} [Note: {notes}]"
        log_user_history(username, "added", details)
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

# === Process User Commands ===

def process_user_commands():
    users = load_user_list()
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
    
    for user_line in users:
        if '---b' in user_line:
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            blocked_users.add(username)
            modified_users.add(username)
            notes = extract_notes_from_line(user_line)
            details = ""
            if notes:
                details = f"[Note: {notes}]"
            log_user_history(username, "blocked", details)
            updated_users.append(user_line)  # Keep command for later processing
        elif '---ub' in user_line:
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            unblocked_users.add(username)
            modified_users.add(username)
            notes = extract_notes_from_line(user_line)
            details = ""
            if notes:
                details = f"[Note: {notes}]"
            log_user_history(username, "unblocked", details)
            updated_users.append(user_line)  # Keep command for later processing
        elif '---d' in user_line:
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            deleted_users.add(username)
            log_user_history(username, "removed", "User deleted")
        elif '---m' in user_line:
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            new_users.add(username)
            details = user_data if user_data else ""
            if notes:
                if details:
                    details = f"{details} [Note: {notes}]"
                else:
                    details = f"[Note: {notes}]"
            log_user_history(username, "added", details)
            create_subscription_file(username)
            updated_users.append(user_line)  # Keep command for later processing
        elif '---r' in user_line:
            any_commands_processed = True
            old_username = extract_username_from_line(user_line)
            command_part = user_line.split('---r')[1]
            if '#' in command_part:
                command_part = command_part.split('#')[0]
            new_username = command_part.strip().split()[0] if command_part.strip() else ''
            if new_username and new_username != old_username:
                renamed_users[old_username] = new_username
                modified_users.add(old_username)
                log_user_history(old_username, "renamed", f"to {new_username}")
                updated_users.append(user_line)  # Keep command for later processing
                rename_subscription_file(old_username, new_username)
            else:
                updated_users.append(user_line)
        elif '---es' in user_line:
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            modified_users.add(username)
            parts = user_line.split('---es')
            if len(parts) > 1:
                time_part = parts[1]
                if '#' in time_part:
                    time_part = time_part.split('#')[0]
                time_part = time_part.strip()
                target_datetime = parse_relative_datetime(time_part)
                if target_datetime:
                    formatted_expiry = format_expiry_datetime(target_datetime)
                    log_user_history(username, "expiry_set", f"{formatted_expiry}")
                    updated_users.append(user_line)  # Keep command for later processing
                else:
                    updated_users.append(user_line)
            else:
                updated_users.append(user_line)
    
    # Organize the user list with new blocked users at top and modified users at top of their sections
    organized_users = organize_user_list(updated_users)
    
    # after processing all commands
    # Save new state after command processing
    save_user_state(organized_users)
    
    # Create a backup if any commands were processed
    if any_commands_processed:
        backup_user_list()
    
    save_user_list(organized_users)
    
    # Create individual backups for each modified user
    for username in modified_users:
        backup_user(username)
    
    # Also backup new usernames from renamed users
    for old_username, new_username in renamed_users.items():
        backup_user(new_username)
    
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
            log_user_history(username, "expired", expiry_time.strftime("%Y-%m-%d %H:%M") if expiry_time else "")
            updated_line = f"{BLOCKED_SYMBOL}{user_line}"
            updated_users.append(updated_line)
        else:
            updated_users.append(user_line)
    if expired_users:
        # Create a backup when users expire
        backup_user_list()
        
        # Organize the user list with newly expired users at the top of blocked section
        organized_users = organize_user_list(updated_users)
        save_user_list(organized_users)
        
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
USER_HISTORY_FILE = 'user_history.txt'
QUARANTINE_DAYS = 3
USER_HISTORY_DAYS = 7  # Keep user history for 7 days
BACKUP_DAYS = 7  # Keep backups for 7 days
SERVER_HISTORY_DAYS = 7  # Keep server history for 7 days
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
    # Check if this user has notes in the user list
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
        # Add new non-working servers to the top of the list
        non_working.insert(0, entry)
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
            sock.settimeout(VALIDATION_TIMEOUT)
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
    timestamp = iran_time.strftime("%Y-%m-%d_%H-%M-%S")  # Added seconds for more precise timestamping
    backup_filename = backup_dir / f"user_list_{timestamp}.txt"
    
    try:
        # Copy the user list to the backup file
        shutil.copy2(USER_LIST_FILE, backup_filename)
        
        # Cleanup old backups (keep those from last BACKUP_DAYS days)
        backups = list(backup_dir.glob("user_list_*.txt"))
        cutoff_date = iran_time - datetime.timedelta(days=BACKUP_DAYS)
        
        for backup_file in backups:
            # Extract date from filename
            try:
                # Format is user_list_YYYY-MM-DD_HH-MM-SS.txt
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
    timestamp = iran_time.strftime("%Y-%m-%d_%H-%M")
    backup_filename = user_dir / f"{username}_{timestamp}.txt"
    
    try:
        # Write the user entry to the backup file
        with open(backup_filename, 'w', encoding='utf-8') as f:
            f.write(user_entry)
        
        # Cleanup old backups (keep latest 10 per user)
        backups = sorted(list(user_dir.glob(f"{username}_*.txt")), key=lambda x: x.stat().st_mtime)
        if len(backups) > 10:  # Keep last 10 backups per user
            for old_file in backups[:-10]:
                old_file.unlink()
                
        return True
    except Exception as e:
        print(f"⚠️ User backup failed for {username}: {str(e)}")
        return False

def update_all_subscriptions():
    """Main entry-point. Behaviour depends on FAST_RUN flag."""

    # Always make a backup of user_list before starting
    if os.path.exists(USER_LIST_FILE):
        backup_user_list()
        # Detect any manual changes since last run
        detect_manual_changes()

    # Always process user commands & expiry first – they are lightweight
    process_user_commands()
    check_expired_users()
    discover_new_subscriptions()
    cleanup_non_working()
    process_non_working_recovery()

    # Server validation and maintenance
    if not FAST_RUN:
        # Heavy maintenance tasks (hourly / scheduled)
        # --- Validate main server list and quarantine non-working entries ---
        current_servers = load_main_servers()
        valid_servers = []

        # Remove obvious fake servers immediately
        servers_to_check = []
        for srv in current_servers:
            if is_fake_server(srv):
                move_server_to_non_working(srv)
            else:
                servers_to_check.append(srv)

        # Parallel TCP validation for the rest
        if servers_to_check:
            max_workers = min(32, len(servers_to_check))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                for srv, ok in zip(servers_to_check, pool.map(validate_server, servers_to_check)):
                    if ok:
                        valid_servers.append(srv)
                    else:
                        move_server_to_non_working(srv)

        # Persist the cleaned list
        save_main_servers(valid_servers)

        # Update remarks & remove duplicates (these are network-bound/CPU heavy)
        all_servers = update_server_remarks(valid_servers)
        unique_servers = remove_duplicates(all_servers)
        save_main_servers(unique_servers)
    else:
        # FAST_RUN → skip all heavy work, use current list as-is
        unique_servers = load_main_servers()

    # Build / update subscription files for every user
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
