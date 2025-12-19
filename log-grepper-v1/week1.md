# 🎯 Today’s Goal (Week 1, Day 1)

By the end of today you should have:

A project folder for Log Grepper.

A working Python script that:

Opens a log file

Counts lines

Counts how many lines contain "ERROR" (or any keyword).

A tiny bit of review of Python basics (variables, loops, file I/O).

This is enough to feel like: “Okay, I’m actually building a security tool.”

1️⃣ Set up the project folder

Create a folder somewhere you like, for example:

log-grepper-v1/
├─ src/
│  └─ log_grepper/
│     └─ __init__.py
├─ sample_logs/
│  └─ app.log
└─ main.py

Minimal steps:

Make log-grepper-v1 directory.

Inside it, make:

src/log_grepper/ (and an empty __init__.py file)

sample_logs/

main.py at the root.

In sample_logs/app.log, paste a few fake lines, like:

2024-12-01T10:00:00Z INFO  User logged in successfully
2024-12-01T10:05:03Z ERROR Failed login for user alice
2024-12-01T10:06:15Z WARN  Slow response from database
2024-12-01T10:07:20Z ERROR Failed login for user bob

2️⃣ (Optional but good) Create a virtual environment

From inside log-grepper-v1:

python -m venv .venv

## Windows

.venv\Scripts\activate

## macOS/Linux

source .venv/bin/activate

For now you don’t need any packages, but this is good muscle memory.

3️⃣ First exercise: count lines & “ERROR” lines

Open main.py and start with something simple:

## main.py

def main():
    log_path = "sample_logs/app.log"  # hard-coded for now
    total_lines = 0
    error_lines = 0

    # Open the file and read line by line
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            total_lines += 1
            if "ERROR" in line:
                error_lines += 1

    print(f"Total lines: {total_lines}")
    print(f'Lines containing "ERROR": {error_lines}')

if __name__ == "__main__":
    main()

Run it:

python main.py

You should see something like:

Total lines: 4
Lines containing "ERROR": 2

🎉 That’s the first baby version of Log Grepper.

4️⃣ Stretch exercise: make the keyword configurable

Next, modify main() so it asks the user for a keyword:

def main():
    log_path = "sample_logs/app.log"
    keyword = input("Enter keyword to search for (e.g. ERROR): ")

    total_lines = 0
    match_lines = 0

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            total_lines += 1
            if keyword in line:
                match_lines += 1

    print(f"Total lines: {total_lines}")
    print(f'Lines containing "{keyword}": {match_lines}')

Later this input() will become command-line args using argparse, but for Day 1, input is fine.

5️⃣ What to read on Programiz today

To support what you just did, on Programiz you can review these topics (in order):

Python Variables & Data Types

Python if...else

Python for Loop

Python File Handling (very important for log reading)

Optionally: Python Functions

As you read:

When they show a file example (open, readline, for line in file:), compare it to your main.py and see if you can improve or simplify your code.

6️⃣ Quick self-check questions for today

Just ask yourself (or answer to me):

How do you open a file safely in Python so it auto-closes?

How do you loop through a file line by line?

How do you check if a substring is in a string?

What happens if the file path is wrong? (You’ll see an exception.)

If you want, you can paste your current main.py in the next message and I’ll:

Review it like a senior engineer,

Suggest one or two “next step” improvements,

Then we’ll move to Day 2: introducing argparse and starting to define parse_line() properly.
