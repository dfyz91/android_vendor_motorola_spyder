#!/bin/sh
set -e

echo "=== Running edl-termux unit and release tests ==="
PYTHONPATH=. python3 -m unittest discover -s tests -p "test_*.py" -v
echo "=== All tests passed! ==="
