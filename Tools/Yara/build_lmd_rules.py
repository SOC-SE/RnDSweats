#!/usr/bin/env python3

"""
LMD Yara Rules Builder

This script is based on the build-rules.py script from the signature-base
repository. It is designed to safely build a single, massive plain-text
'user.yara' file for use with Linux Malware Detect (LMD).

It works by:
1. Walking the './yara' directory.
2. Test-compiling EACH rule file with the dummy external variables LMD fails on.
3. If a file compiles, its text content is appended to the final rule file.
4. If a file fails, it is skipped and logged to 'bad_rules.log'.
"""

import os
import sys
import yara  # install 'yara-python' module
import logging
import traceback
import codecs
import re

# --- Configuration ---
YARA_RULE_DIRECTORIES = ['./yara']
LMD_USER_RULES_FILE = "/usr/local/maldetect/sigs/user.yara"
BAD_RULES_LOG = "/tmp/bad_rules.log"

# Dummy external variables that LMD does not provide, causing errors
DUMMY_EXTERNALS = {
    'filename': "dummy",
    'filepath': "dummy",
    'extension': "dummy",
    'filetype': "dummy",
    'md5': "dummy",
    'filesize': 0
}

# --- Setup Logging ---
# Set up a logger for bad rules
logging.basicConfig(
    filename=BAD_RULES_LOG,
    level=logging.ERROR,
    format='%(asctime)s - %(message)s'
)

def build_lmd_rules():
    """
    Walks directories, test-compiles files, and appends valid rule
    text to the LMD_USER_RULES_FILE.
    """
    total_files_processed = 0
    total_files_added = 0
    total_files_failed = 0

    print(f"Starting Yara build. Final file will be: {LMD_USER_RULES_FILE}")
    print(f"A log of any skipped bad rules will be at: {BAD_RULES_LOG}")
    
    # Clear old rule file and log
    if os.path.exists(LMD_USER_RULES_FILE):
        os.remove(LMD_USER_RULES_FILE)
    if os.path.exists(BAD_RULES_LOG):
        os.remove(BAD_RULES_LOG)

    try:
        # Open the master file to append to
        with open(LMD_USER_RULES_FILE, 'ab') as master_rule_file:
            
            for yara_dir in YARA_RULE_DIRECTORIES:
                if not os.path.exists(yara_dir):
                    print(f"WARNING: Directory not found, skipping: {yara_dir}")
                    continue

                print(f"Processing directory: {yara_dir}")
                for root, directories, files in os.walk(yara_dir, followlinks=False):
                    for file in files:
                        
                        yara_rule_path = os.path.join(root, file)
                        
                        # Skip hidden, backup, or system files
                        if file.startswith(".") or file.startswith("~") or file.startswith("_"):
                            continue
                            
                        # Only process .yar or .yara files
                        extension = os.path.splitext(file)[1].lower()
                        if extension not in ['.yar', '.yara']:
                            continue
                            
                        total_files_processed += 1

                        # --- The Test Compile ---
                        # We try to compile each file individually.
                        # If it succeeds, we add it. If it fails, we log and skip.
                        try:
                            # Test compile with the dummy externals
                            yara.compile(filepath=yara_rule_path, externals=DUMMY_EXTERNALS)
                            
                            # --- COMPILE SUCCESS ---
                            # Read the file's raw text and append it
                            with open(yara_rule_path, 'rb') as rule_file:
                                master_rule_file.write(rule_file.read())
                            # Add a newline for safety
                            master_rule_file.write(b"\n")
                            total_files_added += 1

                        except Exception as e:
                            # --- COMPILE FAILED ---
                            # Log the error and the file that caused it
                            error_msg = f"SKIPPED: File '{yara_rule_path}' failed compile. Error: {e}"
                            print(error_msg, file=sys.stderr)
                            logging.error(error_msg)
                            total_files_failed += 1

    except Exception as e:
        print(f"FATAL ERROR: An unexpected error occurred: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

    print("\n--- Build Complete ---")
    print(f"Total Files Processed: {total_files_processed}")
    print(f"Total Rules Added:     {total_files_added}")
    print(f"Total Rules Skipped:   {total_files_failed}")
    print(f"Master rule file created at: {LMD_USER_RULES_FILE}")
    print(f"Skipped rule log created at: {BAD_RULES_LOG}")

# --- Main Execution ---
if __name__ == '__main__':
    build_lmd_rules()

