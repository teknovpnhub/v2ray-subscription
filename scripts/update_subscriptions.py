import os
import base64
import random
import json
from urllib.parse import urlparse

def extract_server_config(server_line):
    """Extract the core server configuration without remarks"""
    try:
        server_line = server_line.strip()
        
        if server_line.startswith('vmess://'):
            # Decode VMess config
            config_data = base64.b64decode(server_line[8:]).decode('utf-8')
            config = json.loads(config_data)
            # Create unique key from server details (excluding ps/remarks)
            key = f"vmess://{config.get('add')}:{config.get('port')}:{config.get('id')}:{config.get('net')}:{config.get('type')}"
            return key
            
        elif server_line.startswith('vless://'):
            # Parse VLESS URL
            url_part = server_line.split('#')[0]  # Remove remarks
            parsed = urlparse(url_part)
            # Create unique key from core config
            key = f"vless://{parsed.hostname}:{parsed.port}:{parsed.username}:{parsed.path}"
            return key
            
        elif server_line.startswith('ss://'):
            # Parse Shadowsocks
            url_part = server_line.split('#')[0]  # Remove remarks
            parsed = urlparse(url_part)
            key = f"ss://{parsed.hostname}:{parsed.port}:{parsed.username}"
            return key
            
        elif server_line.startswith('trojan://'):
            # Parse Trojan
            url_part = server_line.split('#')[0]  # Remove remarks
            parsed = urlparse(url_part)
            key = f"trojan://{parsed.hostname}:{parsed.port}:{parsed.username}"
            return key
            
        else:
            # For other protocols, use the config without remarks
            return server_line.split('#')[0].strip()
            
    except Exception as e:
        print(f"Error parsing server config: {e}")
        return server_line

def remove_duplicates(servers):
    """Remove duplicate servers based on configuration, not remarks"""
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
            print(f"🔍 Duplicate found:")
            print(f"   Original: {seen_configs[config_key][:80]}...")
            print(f"   Duplicate: {server.strip()[:80]}...")
        else:
            # New unique server
            seen_configs[config_key] = server.strip()
            unique_servers.append(server.strip())
    
    if duplicates_found:
        print(f"📋 Removed {len(duplicates_found)} duplicate servers")
        for dup in duplicates_found:
            original_remark = dup['original'].split('#')[-1] if '#' in dup['original'] else 'No remark'
            duplicate_remark = dup['duplicate'].split('#')[-1] if '#' in dup['duplicate'] else 'No remark'
            print(f"   Kept: {original_remark}")
            print(f"   Removed: {duplicate_remark}")
    else:
        print("✅ No duplicates found")
    
    return unique_servers

def get_blocked_users():
    """Read blocked users from blocked_users.txt"""
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
    """Check if a user should be blocked"""
    return username in blocked_users

def get_fake_servers():
    """Return fake/non-working servers for blocked users"""
    fake_servers = [
        "vmess://eyJ2IjoiMiIsInBzIjoiRmFrZSBTZXJ2ZXIgMSIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOiI4MCIsInR5cGUiOiJub25lIiwiaWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODkwYWIiLCJhaWQiOiIwIiwibmV0Ijoid3MiLCJwYXRoIjoiLyIsImhvc3QiOiIiLCJ0bHMiOiIifQ==",
        "vless://12345678-1234-1234-1234-123456789abc@127.0.0.1:443?encryption=none&security=tls&type=ws&path=%2F#Fake%20Server%202",
        "ss://YWVzLTI1Ni1nY206ZmFrZXBhc3N3b3Jk@127.0.0.1:8388#Fake%20Server%203"
    ]
    return fake_servers

def distribute_servers(servers, username):
    """Distribute real servers to active users"""
    if not servers:
        return get_fake_servers()
    
    # Simple distribution - give all servers to active users
    # You can modify this logic for more sophisticated distribution
    return servers

def update_all_subscriptions():
    """Update all subscription files with servers from main.txt"""
    
    # Read servers from main.txt
    try:
        with open('main.txt', 'r', encoding='utf-8') as f:
            all_servers = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print("❌ main.txt not found")
        return
    
    print(f"📖 Read {len(all_servers)} servers from main.txt")
    
    # Remove duplicates
    unique_servers = remove_duplicates(all_servers)
    
    # Update main.txt if duplicates were removed
    if len(unique_servers) < len(all_servers):
        print(f"💾 Updating main.txt: {len(all_servers)} → {len(unique_servers)} servers")
        with open('main.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_servers) + '\n')
    
    # Get blocked users
    blocked_users = get_blocked_users()
    
    # Process subscription files
    subscription_dir = 'subscriptions'
    if not os.path.exists(subscription_dir):
        os.makedirs(subscription_dir)
        print(f"📁 Created {subscription_dir} directory")
    
    # Get all .txt files in subscriptions directory
    subscription_files = [f for f in os.listdir(subscription_dir) if f.endswith('.txt')]
    
    if not subscription_files:
        print("⚠️  No subscription files found in subscriptions/ directory")
        return
    
    print(f"🔄 Processing {len(subscription_files)} subscription files...")
    
    for filename in subscription_files:
        username = filename[:-4]  # Remove .txt extension
        
        if should_block_user(username, blocked_users):
            servers_for_user = get_fake_servers()
            print(f"🚫 {filename}: Blocked user - using {len(servers_for_user)} fake servers")
        else:
            servers_for_user = distribute_servers(unique_servers, username)
            print(f"✅ {filename}: Active user - {len(servers_for_user)} real servers")
        
        # Write to subscription file
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
