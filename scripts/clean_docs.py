import os
import re

current_dir = os.path.dirname(os.path.abspath(__file__))
base_docs_path = os.path.join(current_dir, '..', 'docs', 'src')
directories = [base_docs_path, os.path.join(base_docs_path, 'secrets')]

meta_pattern = re.compile(r'^\*\*(Document Version|Last Updated|Classification|Author):\*\*.*?\n', re.MULTILINE)

for d in directories:
    if not os.path.exists(d):
        continue
    for filename in os.listdir(d):
        if not filename.endswith('.md') or filename in ['README.md', 'SUMMARY.md']:
            continue
        
        filepath = os.path.join(d, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Clean title: e.g. "# Research Note 1: Vision, Mission, and Purpose" -> "# Vision, Mission, and Purpose"
        # Also matching "# Classified Security Mechanisms 1: ..."
        content = re.sub(r'^(#\s+)(Research Note \d+: |Classified Security Mechanisms?:? ?\d*:? )', r'\1', content, count=1, flags=re.MULTILINE)
        
        # Remove the metadata lines
        content = re.sub(meta_pattern, '', content)
        
        # Remove any lingering empty "---\n\n---" blocks left after removing metadata
        content = re.sub(r'^---\s*\n\s*---\s*\n', '---\n', content, flags=re.MULTILINE)
        
        # Sometimes metadata is wrapped in --- block, so if there's an empty one at the start:
        content = re.sub(r'^(# .*?\n+)^---\s*\n\s+^---\s*\n', r'\1', content, flags=re.MULTILINE)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

print(f"Batch processed all markdown files in {directories}.")
