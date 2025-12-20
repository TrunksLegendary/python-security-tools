"""Simple log search tool using argparse."""
import argparse
import re

pat = re.compile(r"failed password", re.IGNORECASE)

def parse_arg() -> argparse.Namespace:
    """Parse command-line arguments for the log search tool."""
    parser = argparse.ArgumentParser(
        description="Search a log file for a keyword and count matches"
    )
    parser.add_argument(
        "-i",
        "--input",
        required=False,
        default="sample_logs/app.log",
        help="Path to the log file"
    )

    parser.add_argument(
        "-k", 
        "--keyword", 
        required=False, help="Keyword to search for"
    )

    return parser.parse_args()

def main() -> None:
    """Run the log search using the parsed arguments."""
    args = parse_arg()
    log_path = args.input
    keyword = args.keyword
    total_lines = 0
    match_lines = 0

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            if keyword.lower() in line.lower():
                print(line.strip())
                match_lines += 1

            if pat.search(line):
                print("Found failed password")

    print(f"total lines: {total_lines}")
    print(f'Lines contiaining "{keyword}": {match_lines}')

if __name__ == "__main__":
    main()
# End of file
