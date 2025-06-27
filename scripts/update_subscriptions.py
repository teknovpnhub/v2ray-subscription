# scripts/update_subscriptions.py
import base64
import os
import glob

def read_file(file_path: str) -> str:
    """Read file content"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read().strip()

def write_file(file_path: str, content: str):
    """Write content to file"""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

def update_subscription_files():
    # Read main.txt content
    main_content = read_file('main.txt')
    
    # Encode content in base64 (V2Ray subscription format)
    encoded_content = base64.b64encode(main_content.encode()).decode()
    
    # Create subscriptions directory if it doesn't exist
    os.makedirs('subscriptions', exist_ok=True)
    
    # Create default subscription files if none exist
    subscription_files = glob.glob('subscriptions/*.txt')
    if not subscription_files:
        # Create at least one default file
        write_file('subscriptions/default.txt', encoded_content)
    else:
        # Update all existing subscription files
        for sub_file in subscription_files:
            write_file(sub_file, encoded_content)

def main():
    update_subscription_files()

if __name__ == '__main__':
    main()
