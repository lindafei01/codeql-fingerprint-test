#!/bin/bash
# Script for analyzing vulnerability differences between commits using CodeQL

# Configuration
REPO_PATH="/path/to/your/repository"
COMMIT_ID="abc123"  # The commit you want to analyze
LANGUAGE="python"  # Change to your language (javascript, java, cpp, csharp, python, etc.)
QUERY_SUITE="security-extended"  # You can use security-and-quality, security-extended, etc.

# Step 1: Create a CodeQL database for the version before the commit
echo "Creating CodeQL database for the version before the commit..."
cd $REPO_PATH
git checkout $COMMIT_ID~1  # checkout the commit before the target
codeql database create ../codeql_db_before --language=$LANGUAGE --source-root .

# Step 2: Create a CodeQL database for the version after the commit
echo "Creating CodeQL database for the version after the commit..."
git checkout $COMMIT_ID  # checkout the target commit
codeql database create ../codeql_db_after --language=$LANGUAGE --source-root .

# Step 3: Run the analysis on both databases
echo "Running CodeQL analysis on the version before the commit..."
codeql database analyze ../codeql_db_before --format=sarif-latest --output=../results_before.sarif $QUERY_SUITE

echo "Running CodeQL analysis on the version after the commit..."
codeql database analyze ../codeql_db_after --format=sarif-latest --output=../results_after.sarif $QUERY_SUITE

# Step 4: Compare the results using a more robust approach that handles code shifts
echo "Comparing results..."
python3 - << EOF
import json
import os
import re
import subprocess
from collections import defaultdict

# Load SARIF files
with open('../results_before.sarif', 'r') as f:
    before_data = json.load(f)
    
with open('../results_after.sarif', 'r') as f:
    after_data = json.load(f)

# Function to extract code fingerprints from results
def extract_fingerprints(sarif_data):
    fingerprints = defaultdict(list)
    
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            # Get the file path
            loc = result.get('locations', [{}])[0].get('physicalLocation', {})
            file_path = loc.get('artifactLocation', {}).get('uri', '')
            
            # Get the code snippet - if available
            region = loc.get('region', {})
            start_line = region.get('startLine', 0)
            snippet = result.get('codeFlows', [])
            
            # Get rule and message information
            rule_id = result.get('ruleId', '')
            message = result.get('message', {}).get('text', '')
            
            # Try to use partialFingerprints if available
            partial_fingerprints = result.get('partialFingerprints', {})
            if partial_fingerprints:
                for key, value in partial_fingerprints.items():
                    if 'fingerprint' in key.lower():
                        fingerprints[value].append({
                            'file': file_path,
                            'line': start_line,
                            'rule_id': rule_id,
                            'message': message
                        })
                        break
            else:
                # Create a fingerprint based on the rule and message content
                # This is less accurate but better than just comparing locations
                content_hash = f"{rule_id}:{re.sub(r'[0-9]+', 'N', message)}"
                fingerprints[content_hash].append({
                    'file': file_path,
                    'line': start_line,
                    'rule_id': rule_id,
                    'message': message
                })
    
    return fingerprints

# Extract fingerprints from both before and after
before_fingerprints = extract_fingerprints(before_data)
after_fingerprints = extract_fingerprints(after_data)

# Find new vulnerability fingerprints
new_fingerprint_keys = set(after_fingerprints.keys()) - set(before_fingerprints.keys())

# Get details about the modified files in this commit
os.chdir('$REPO_PATH')
modified_files = subprocess.check_output(['git', 'diff', '--name-only', '$COMMIT_ID~1', '$COMMIT_ID']).decode('utf-8').splitlines()

# Display results
new_issues_count = sum(len(after_fingerprints[key]) for key in new_fingerprint_keys)
print(f"Found {new_issues_count} new potential vulnerabilities in commit {'$COMMIT_ID'}")

for key in new_fingerprint_keys:
    for issue in after_fingerprints[key]:
        # Check if this issue is in a modified file
        relative_path = issue['file']
        if relative_path in modified_files:
            print(f"[{issue['rule_id']}] {issue['file']}:{issue['line']}: {issue['message']}")
            print(f"  - This issue appears in a file modified by the commit")
        else:
            print(f"[{issue['rule_id']}] {issue['file']}:{issue['line']}: {issue['message']}")
            print(f"  - This file was NOT modified in this commit (possible false positive)")

print("\nNote: This analysis uses CodeQL's fingerprinting to identify unique issues")
print("rather than just comparing line numbers, which helps handle code shifts.")
EOF

echo "Analysis complete!"