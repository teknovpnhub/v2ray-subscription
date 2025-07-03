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

# === New Server Remark and Flag Functions ===

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

        # Check if custom remark requested (--- present)
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

# === The rest of your original code remains unchanged ===

# ... (keep all your previous functions: duplicate detection, quarantine, etc.)

def load_main_servers():
    if not os.path.exists('main.txt'):
        return []
    with open('main.txt', 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def save_main_servers(servers):
    with open('main.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(servers) + '\n')

def update_all_subscriptions():
    all_servers = load_main_servers()
    all_servers = update_server_remarks(all_servers)
    unique_servers = remove_duplicates(all_servers)
    save_main_servers(unique_servers)
    # ...rest of your update logic (blocked users, subscriptions, etc.)

if __name__ == "__main__":
    # ...your quarantine/test logic if needed
    update_all_subscriptions()
