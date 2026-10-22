"""Run the five regular Lab 3 questions with displayed defaults."""

# Use the current interpreter so all questions see the same installed packages.
from pathlib import Path
import subprocess
import sys



# ---------- RUN ALL REGULAR EXERCISES ----------
# Run each question with blank inputs to select its displayed defaults.
# Use sys.executable so every child program uses this same Python environment.
def main():
    for script in sorted(Path(__file__).resolve().parent.glob("q*.py")):
        print("\n" + "=" * 65, flush=True)
        print(script.stem, flush=True)
        print("=" * 65, flush=True)
        subprocess.run([sys.executable, str(script)], input="\n" * 16,
                       text=True, check=True)


# Individual questions remain separately runnable from PyCharm.
if __name__ == "__main__":
    main()
