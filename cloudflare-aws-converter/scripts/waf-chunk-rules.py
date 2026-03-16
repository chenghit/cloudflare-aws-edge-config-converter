#!/usr/bin/env python3
"""Chunk WAF-Custom-Rules.txt into smaller JSON files for parallel validation.

Usage:
    python3 waf-chunk-rules.py <config_path> <output_dir> <chunk_size>

Reads WAF-Custom-Rules.txt from config_path (searches recursively),
splits the rules array into chunks of chunk_size, and writes each chunk
as a bare JSON array to output_dir/chunks/custom-rules-{start}-{end}.json.

Prints the chunk file paths to stdout (one per line) for the orchestrator.
"""
import json, sys, os, math

config_path = sys.argv[1]
output_dir = sys.argv[2]
chunk_size = int(sys.argv[3])

# Find WAF-Custom-Rules.txt
custom_path = None
for root, dirs, files in os.walk(config_path):
    for f in files:
        if f == "WAF-Custom-Rules.txt":
            custom_path = os.path.join(root, f)
            break
    if custom_path:
        break

if not custom_path:
    print("ERROR: WAF-Custom-Rules.txt not found")
    sys.exit(1)

data = json.load(open(custom_path))
if isinstance(data.get("result"), dict) and "rules" in data["result"]:
    rules = data["result"]["rules"]
elif isinstance(data.get("result"), list):
    rules = data["result"]
else:
    print("ERROR: Cannot parse rules from WAF-Custom-Rules.txt")
    sys.exit(1)

total = len(rules)
if total == 0:
    print("NO_RULES")
    sys.exit(0)

chunks_dir = os.path.join(output_dir, "chunks")
os.makedirs(chunks_dir, exist_ok=True)

num_chunks = math.ceil(total / chunk_size)
for i in range(num_chunks):
    start = i * chunk_size
    end = min((i + 1) * chunk_size, total)
    chunk = rules[start:end]
    # 1-indexed naming for human readability
    filename = f"custom-rules-{start + 1}-{end}.json"
    filepath = os.path.join(chunks_dir, filename)
    json.dump(chunk, open(filepath, "w"), indent=2)
    print(filepath)
