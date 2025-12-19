import argparse
import re
import json
from collections import Counter


IP_REGEX = re.compile(r"ip=(\d+\.\d+\.\d+\.\d+)")


def run(path, matches, max_print, jsonl_out=None, count_only=False):
    printed = 0
    total = 0
    ip_counts = Counter()
    

    out_f = open(jsonl_out, "w", encoding="utf-8") if jsonl_out else None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.rstrip("\n")
                if not matches(line):
                    continue
                
                total += 1
                
                
                ip_match = IP_REGEX.search(line)
                if ip_match:
                        ip_counts[ip_match.group(1)] += 1
                
                if not count_only and printed < max_print:
                        print(f"{line_num}: {line}")
                        printed += 1

                    
                # write JSONL
                if out_f:
                        rec = {"line": line_num, "text": line}
                        out_f.write(json.dumps(rec) + "\n")
                        
            if count_only == True:
                print(f"Matches found : {total}")
    finally:
        if out_f:
            out_f.close()

    print(f"\nMatches found: {total}")
    if total > max_print and not count_only:
        print(f"(Printed first {max_print} only)")

    if ip_counts:
        print("\nTop IPs:")
        for ip, count in ip_counts.most_common(3):
            print(f" {ip}: {count}")


def make_matcher(keyword, regex, ignore_case):
    
    flags = re.IGNORECASE if ignore_case else 0
    rx = re.compile(regex, flags) if regex else None
    kw = keyword.lower() if (keyword and ignore_case) else keyword

    def matches(line):
        test_line = line.lower() if ignore_case else line
        if kw and kw not in test_line:
            return False
        if rx and not rx.search(line):
            return False
        return True

    return matches

def build_args():
    
    p = argparse.ArgumentParser(
        description="Log Grepper v2 (Day 3)",
    )
    
    p.add_argument(
        "path", 
        help="Path to log file",
    )
    
    p.add_argument(
        "-k", 
        "--keyword", 
        help="Simple subscript match",
        )
    
    p.add_argument(
        "-r", 
        "--regex", 
        help="Regex match (Python re)",
        )
    
    p.add_argument(
        "--ignore-case", 
        action="store_true", 
        help="Case insensitive matching",
    )
    
    p.add_argument(
        "--max", 
        type=int, 
        default=50, 
        help="Max lines to print (default 50)",
    )
    
    p.add_argument(
        "--jsonl", 
        help="Write matches to JSONL file",
        )
    
    p.add_argument(
        "--count-only",
        action="store_true",
        help=" Only print summary counts and top IPs (no matching linesd).",
    )
    
    
    return p

def main():
    args = build_args().parse_args()
    matcher = make_matcher(args.keyword, 
                           args.regex, 
                           args.ignore_case)
    
    run(args.path, 
        matcher, 
        args.max, 
        args.jsonl, 
        count_only=args.count_only)

if __name__ == "__main__":
    main()
