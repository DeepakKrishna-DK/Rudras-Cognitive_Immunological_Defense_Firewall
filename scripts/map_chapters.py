import os
import re

current_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.join(current_dir, '..', 'docs', 'src')
summary_path = os.path.join(base_path, 'SUMMARY.md')

with open(summary_path, 'r', encoding='utf-8') as f:
    summary_lines = f.readlines()

for line in summary_lines:
    # Match strings exactly like: - [1. How companies can benefit from Rudras](vision_and_purpose.md)
    match = re.search(r'\[(.*?)\]\((.*?)\)', line)
    if not match:
        continue
        
    title = match.group(1).replace('Rudras: The Firewall in Practice', '🛡️ Welcome to Rudras Documentation')
    rel_path = match.group(2)
    filepath = os.path.join(base_path, rel_path)
    
    if os.path.exists(filepath) and rel_path != "README.md":
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
            
        # Replace the first H1 tag (# Something) with the actual book Title string
        content = re.sub(r'^# .*', f'# {title}', content, count=1, flags=re.MULTILINE)
        
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(content)
            
print("Successfully mapped Book Chapter Titles to all internal Markdown Files.")
