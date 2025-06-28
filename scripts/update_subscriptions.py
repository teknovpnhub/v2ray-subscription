import base64
import os
import glob
import json

def read_file(file_path: str) -> str:
    """Read file content"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read().strip()

def write_file(file_path: str, content: str):
    """Write content to file"""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

def create_fake_servers():
    """Create fake/non-working server configurations"""
    fake_configs = [
        {
            "v": "2",
            "ps": "Server Maintenance",
            "add": "127.0.0.1",  # localhost - won't work for clients
            "port": "443",
            "id": "00000000-0000-0000-0000-000000000000",  # fake UUID
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "",
            "path": "/",
            "tls": "tls"
        },
        {
            "v": "2", 
            "ps": "Contact Admin",
            "add": "192.0.2.1",  # RFC 5737 test IP - won't work
            "port": "80",
            "id": "11111111-1111-1111-1111-111111111111",  # fake UUID
            "aid": "0",
            "net": "tcp",
            "type": "none",
            "host": "",
            "path": "",
            "tls": ""
        }
    ]
    
    # Convert to vmess:// format
    fake_vmess_links = []
    for config in fake_configs:
        config_json = json.dumps(config)
        config_b64 = base64.b64encode(config_json.encode()).decode()
        vmess_link = f"vmess://{config_b64}"
        fake_vmess_links.append(vmess_link)
    
    return "\n".join(fake_vmess_links)

def get_blocked_users():
    """Get list of users who should get fake servers"""
    blocked_users = []
    
    # Method 1: Read from blocked_users.txt file
    if os.path.exists('blocked_users.txt'):
        try:
            with open('blocked_users.txt', 'r', encoding='utf-8') as f:
                blocked_users = [line.strip() for line in f if line.strip()]
        except:
            pass
    
    # Method 2: Read from environment variable (GitHub secrets)
    env_blocked = os.environ.get('BLOCKED_USERS', '')
    if env_blocked:
        blocked_users.extend([user.strip() for user in env_blocked.split(',')])
    
    return list(set(blocked_users))  # Remove duplicates

def should_block_user(sub_file: str) -> bool:
    """Check if this user should get fake servers"""
    # Extract username from filename (remove .txt extension)
    filename = os.path.basename(sub_file)
    username = filename.replace('.txt', '')
    
    blocked_users = get_blocked_users()
    return username in blocked_users

def update_subscription_files():
    """Update subscription files with real or fake content based on blocking list"""
    
    # Check if main.txt exists
    if not os.path.exists('main.txt'):
        print("❌ ERROR: main.txt not found!")
        return
    
    # Read real content from main.txt
    real_content = read_file('main.txt')
    if not real_content:
        print("❌ ERROR: main.txt is empty!")
        return
    
    real_encoded = base64.b64encode(real_content.encode()).decode()
    
    # Create fake content
    fake_content = create_fake_servers()
    fake_encoded = base64.b64encode(fake_content.encode()).decode()
    
    # Create subscriptions directory if it doesn't exist
    os.makedirs('subscriptions', exist_ok=True)
    
    # Get all subscription files
    subscription_files = glob.glob('subscriptions/*.txt')
    
    if not subscription_files:
        print("⚠️  No subscription files found in subscriptions/ directory")
        return
    
    print(f"📁 Found {len(subscription_files)} subscription files")
    
    # Get blocked users list for logging
    blocked_users = get_blocked_users()
    if blocked_users:
        print(f"🚫 Blocked users: {blocked_users}")
    else:
        print("✅ No users blocked")
    
    # Update each subscription file
    updated_count = 0
    for sub_file in subscription_files:
        filename = os.path.basename(sub_file)
        username = filename.replace('.txt', '')
        
        print(f"\n🔍 Processing: {filename}")
        
        # Determine what content THIS USER should get
        if should_block_user(sub_file):
            intended_content = fake_encoded
            status_type = "FAKE SERVERS"
            emoji = "🚫"
        else:
            intended_content = real_encoded  
            status_type = "REAL SERVERS"
            emoji = "✅"
        
        # Read current content
        current_content = ''
        try:
            current_content = read_file(sub_file)
        except Exception as e:
            print(f"   📄 File read error: {e}")
        
        # ALWAYS UPDATE if file is empty OR content is different
        if not current_content:
            # File is empty - populate it
            write_file(sub_file, intended_content)
            print(f"   🆕 CREATED: {emoji} {username} → {status_type}")
            updated_count += 1
        elif current_content != intended_content:
            # File has different content - update it
            write_file(sub_file, intended_content)
            print(f"   📝 UPDATED: {emoji} {username} → {status_type}")
            updated_count += 1
        else:
            # File already has correct content
            print(f"   ⏭️  NO CHANGE: {emoji} {username} → {status_type}")
    
    print(f"\n✨ Summary: {updated_count} files updated out of {len(subscription_files)} total")

def main():
    print("🔄 Starting V2Ray subscription update...")
    print(f"📍 Working directory: {os.getcwd()}")
    print(f"📁 Files in current directory: {os.listdir('.')}")
    
    update_subscription_files()
    
    print("✨ Update completed!")

if __name__ == '__main__':
    main()
