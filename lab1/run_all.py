"""Run all regular exercises using their manual defaults (blank inputs)."""

from pathlib import Path
import subprocess
import sys



# ---------- RUN ALL REGULAR EXERCISES ----------
# Run each question with blank inputs to select its displayed defaults.
# Use sys.executable so every child program uses this same Python environment.
def main():
    folder = Path(__file__).resolve().parent
    for script in sorted(folder.glob('q*.py')):
        print('\n' + '=' * 60, flush=True)
        print(script.stem, flush=True)
        print('=' * 60, flush=True)
        subprocess.run([sys.executable, str(script)], input='\n' * 8,
                       text=True, check=True)


if __name__ == '__main__':
    main()
