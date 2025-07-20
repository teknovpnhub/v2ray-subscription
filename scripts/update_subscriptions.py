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
    if '#' in clean_line:
        clean_line = clean_line.split('#')[0].strip()

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
    # Regex matches optional whitespace, a pipe, the word 'blocked' and a date.
    cleaned = re.sub(r"\s*\|\s*blocked\s+\d{4}-\d{2}-\d{2}", "", note)
    return cleaned.strip()

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
        # If the new file already exists, generate a unique username
        if os.path.exists(new_file):
            original_new_username = new_username
            new_username = generate_unique_username(new_username)
            new_file = os.path.join(subscription_dir, f"{new_username}.txt")
            print(f"⚠️ Subscription file {original_new_username}.txt already exists, using {new_username}.txt instead")
            log_user_history(new_username, "auto_renamed", f"Automatically renamed from {original_new_username} due to duplicate subscription file")
            
        os.rename(old_file, new_file)
        print(f"📄 Renamed subscription file: {old_username}.txt → {new_username}.txt")
        return new_username  # Return the potentially modified username
    else:
        print(f"⚠️ Subscription file not found: {old_username}.txt")
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
        if '---b' in user_line:
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            # Remove any existing command tokens and pipe-notes before extracting user_data
            cleaned_line = user_line.split('---')[0].split('|')[0].strip()
            user_data = extract_user_data_from_line(cleaned_line)
            notes = extract_notes_from_line(user_line)
            blocked_users.add(username)
            modified_users.add(username)
            users_to_top.add(username)  # Move to top when blocked
            # Add block date note (Iran time)
            block_date = get_iran_time().strftime("%Y-%m-%d")
            date_note = f"| blocked {block_date}"
            # Avoid duplicating the block-date note
            if date_note not in notes:
                if notes:
                    notes = f"{notes} {date_note}"
                else:
                    notes = date_note

            # Prepend '#' symbol to notes (if any) to retain comment marker (no space after '#')
            notes_with_hash = f"#{notes}" if notes else ""

            details = date_note
            # Let log_user_history handle adding the note
            log_user_history(username, "blocked", details)
            if user_data and notes_with_hash:
                updated_line = f"{BLOCKED_SYMBOL}{username} {user_data} {notes_with_hash}"
            elif user_data:
                updated_line = f"{BLOCKED_SYMBOL}{username} {user_data}"
            elif notes_with_hash:
                updated_line = f"{BLOCKED_SYMBOL}{username} {notes_with_hash}"
            else:
                updated_line = f"{BLOCKED_SYMBOL}{username}"
            updated_users.append(updated_line)
        elif '---ub' in user_line:
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            # Clean any old block-date tags from the note when unblocking
            raw_notes = extract_notes_from_line(user_line)
            notes = strip_block_dates(raw_notes)
            unblocked_users.add(username)
            modified_users.add(username)
            users_to_top.add(username)  # Move to top when unblocked
            details = ""
            # Let log_user_history handle adding the note
            log_user_history(username, "unblocked", details)
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
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            deleted_users.add(username)
            log_user_history(username, "removed", "User deleted")
        elif '---m' in user_line:
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            # Auto-generate a unique username if none was provided (i.e. the line is just "---m" + optional note)
            if not username:
                username = generate_unique_username("customer")
                print(f"\u2699\ufe0f Auto-generated username: {username}")
            
            # Check if username already exists and generate a unique one if needed
            original_username = username
            # Exclude the current line from duplicate check to avoid false positives
            existing_usernames = [extract_username_from_line(u) for u in users if u is not user_line]
            existing_updated_usernames = [extract_username_from_line(u) for u in updated_users]
            
            # Debug print to help identify the issue
            print(f"Adding user: {username}")
            print(f"Existing usernames: {existing_usernames}")
            
            if username in existing_updated_usernames or username in existing_usernames:
                username = generate_unique_username(username)
                log_user_history(username, "auto_renamed", f"Automatically renamed from {original_username} due to duplicate")
                print(f"⚠️ Username {original_username} already exists, using {username} instead")
            
            new_users.add(username)
            details = user_data if user_data else ""
            # Let log_user_history handle adding the note
            log_user_history(username, "added", details)
            
            # Create subscription file
            create_subscription_file(username)
            
            # Add user to updated_users list
            if user_data and notes:
                updated_line = f"{username} {user_data} #{notes}"
            elif user_data:
                updated_line = f"{username} {user_data}"
            elif notes:
                updated_line = f"{username} #{notes}"
            else:
                updated_line = username
            updated_users.append(updated_line)
            
            # Add to users_to_top to ensure it's moved to the top
            users_to_top.add(username)
        elif '---r' in user_line:
            any_commands_processed = True
            old_username = extract_username_from_line(user_line)
            user_data = extract_user_data_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            command_part = user_line.split('---r')[1]
            if '#' in command_part:
                command_part = command_part.split('#')[0]
            new_username = command_part.strip().split()[0] if command_part.strip() else ''
            if new_username and new_username != old_username:
                renamed_users[old_username] = new_username
                modified_users.add(old_username)
                users_to_top.add(new_username)  # Move to top when renamed
                # Will backup the new username after processing
                log_user_history(old_username, "renamed", f"to {new_username}")
                symbol = BLOCKED_SYMBOL if user_line.startswith(BLOCKED_SYMBOL) else ''
                
                # Rename subscription file - this might return a different username if there's a conflict
                actual_new_username = rename_subscription_file(old_username, new_username)
                
                # If the username was changed due to a conflict, update our tracking
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
        elif '---es' in user_line:
            any_commands_processed = True
            username = extract_username_from_line(user_line)
            notes = extract_notes_from_line(user_line)
            modified_users.add(username)
            users_to_top.add(username)  # Move to top when expiry is set
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
                    log_user_history(username, "expiry_set", f"{formatted_expiry}")
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
    # Write blocked list so that freshly blocked users appear first
    ordered_blocked = list(blocked_users) + [u for u in all_blocked if u not in blocked_users]
    with open('blocked_users.txt', 'w', encoding='utf-8') as f:
        for user in ordered_blocked:
            f.write(f"{user}\n")
    subscription_dir = 'subscriptions'
    for username in deleted_users:
        sub_file = os.path.join(subscription_dir, f"{username}.txt")
        if os.path.exists(sub_file):
            os.remove(sub_file)

# === BLOCKED USERS FILE COMMANDS ===

def process_blocked_users_commands():
    """Allow admin to put command flags (---ub / ---b) inside blocked_users.txt.
    The function will read blocked_users.txt, process any directives, sync changes
    back to user_list.txt, and rewrite blocked_users.txt without the flags.
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

    to_block = {}
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
        elif '---b' in line:
            username = extract_username_from_line(line)
            note = extract_notes_from_line(line)
            if username:
                to_block[username] = note
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
        elif uname in to_block:
            # Ensure blocked symbol present and update/add note
            # Remove existing note to replace
            base_without_note = remove_notes_from_line(user_line.lstrip(BLOCKED_SYMBOL).lstrip())
            # Compose note with block date
            iran_date = get_iran_time().strftime("%Y-%m-%d")
            date_note = f"| blocked {iran_date}"
            note_input = to_block.get(uname, '')
            # Build note ensuring we don't duplicate date
            if date_note in note_input:
                note = note_input.strip()
            else:
                note = f"{note_input} {date_note}".strip()

            # Prepend '#' symbol to note (if any) (no space after '#')
            note_with_hash = f"#{note}" if note else ""
            blocked_line = f"{BLOCKED_SYMBOL}{base_without_note}"
            if note_with_hash:
                blocked_line += f" {note_with_hash}"
            elif '#' in user_line:
                # Reattach existing note if no new note specified
                old_note = extract_notes_from_line(user_line)
                blocked_line += f" #{old_note}"
            updated_users.append(blocked_line)
            modified_users.add(uname)
            log_user_history(uname, "blocked", "via blocked_users.txt")
        else:
            updated_users.append(user_line)

    # Add new blocked entries which were not in user_list
    for uname, note in to_block.items():
        if uname not in existing_usernames:
            line = f"{BLOCKED_SYMBOL}{uname}"
            if note:
                line += f" {note}"
            updated_users.append(line)
            modified_users.add(uname)
            log_user_history(uname, "blocked", "via blocked_users.txt (new user)")

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

    # Re-write blocked_users.txt putting freshly blocked usernames at the top
    # Build final blocked list preserving notes, newest blocks first
    new_block_list = []
    for uname, note_in in to_block.items():
        iran_date = get_iran_time().strftime("%Y-%m-%d")
        date_note = f"| blocked {iran_date}"
        if date_note in note_in:
            note = note_in.strip()
        else:
            note = f"{note_in} {date_note}".strip()
        entry = uname
        if note:
            entry += f" #{note}"
        new_block_list.append(entry)
    # Add remaining lines (plain keeps) that are still blocked
    for ln in keep_plain:
        u = extract_username_from_line(ln)
        if u not in to_unblock and u not in to_delete and u not in to_block:  # still blocked and not deleted or reblocked this run
            new_block_list.append(ln)
    with open(blocked_file, 'w', encoding='utf-8') as f:
        for uname in new_block_list:
            f.write(f"{uname}\n")

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
    # Process any commands written directly inside blocked_users.txt
    process_blocked_users_commands()
    check_expired_users()

    if not FAST_RUN:
        # Heavy maintenance tasks (hourly / scheduled)
        discover_new_subscriptions()
        cleanup_non_working()
        process_non_working_recovery()

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
