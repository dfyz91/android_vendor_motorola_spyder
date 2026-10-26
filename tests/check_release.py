"""Automated check verifying that no mock/simulation code exists in the production runtime."""
import os
import sys

RUNTIME_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "edl_termux"))

FORBIDDEN_PATTERNS = [
    "mock_device",
    "MockDevice",
    "PipeTransport",
    "RawFdTransport",
    "--mock",
]

def check_runtime_clean():
    errors = []
    for root, dirs, files in os.walk(RUNTIME_DIR):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                if "mock" in file.lower():
                    errors.append(f"Forbidden mock file in runtime: {file}")
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    for pat in FORBIDDEN_PATTERNS:
                        if pat in content:
                            errors.append(f"Forbidden pattern '{pat}' found in {os.path.relpath(path, RUNTIME_DIR)}")

    if errors:
        print("Release Audit Failed:")
        for err in errors:
            print(" -", err)
        sys.exit(1)
    else:
        print("Release Audit Passed: No mock/test artifacts found in production runtime edl_termux.")

if __name__ == "__main__":
    check_runtime_clean()
