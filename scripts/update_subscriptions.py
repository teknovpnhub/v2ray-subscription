def update_subscription_files():
    """Update subscription files with real or fake content based on blocking list"""
    
    # Read real content from main.txt
    real_content = read_file('main.txt')
    real_encoded = base64.b64encode(real_content.encode()).decode()
    
    # Create fake content
    fake_content = create_fake_servers()
    fake_encoded = base64.b64encode(fake_content.encode()).decode()
    
    # Create subscriptions directory if it doesn't exist
    os.makedirs('subscriptions', exist_ok=True)
    
    # Get all subscription files
    subscription_files = glob.glob('subscriptions/*.txt')
    
    # Get blocked users list for logging
    blocked_users = get_blocked_users()
    if blocked_users:
        print(f"🚫 Blocked users: {blocked_users}")
    else:
        print("✅ No users blocked")
    
    # Update each subscription file
    for sub_file in subscription_files:
        filename = os.path.basename(sub_file)
        username = filename.replace('.txt', '')
        
        # Determine what content THIS USER should get
        if should_block_user(sub_file):
            intended_content = fake_encoded
            status = f"🚫 {username} → FAKE SERVERS"
        else:
            intended_content = real_encoded  
            status = f"✅ {username} → REAL SERVERS"
        
        # Read current content
        current_content = ''
        try:
            current_content = read_file(sub_file)
        except:
            pass
        
        # UPDATE: Always update if file is empty OR content differs
        if not current_content or current_content != intended_content:
            write_file(sub_file, intended_content)
            if not current_content:
                print(f"🆕 Created {status}")  # New file
            else:
                print(f"📝 Updated {status}")  # Updated file
        else:
            print(f"⏭️  No change {status}")
