"""Run the five REGULAR Lab 2 questions with their displayed defaults."""

from pathlib import Path
import subprocess
import sys


def main():
    for script in sorted(Path(__file__).resolve().parent.glob("q*.py")):
        print("\n" + "=" * 65, flush=True)
        print(script.stem, flush=True)
        print("=" * 65, flush=True)
        subprocess.run([sys.executable, str(script)], input="\n" * 8,
                       text=True, check=True)


if __name__ == "__main__":
    main()
