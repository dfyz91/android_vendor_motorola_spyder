"""Unit test for release audit clean check."""
import unittest
from tests.check_release import check_runtime_clean


class TestReleaseClean(unittest.TestCase):

    def test_runtime_clean(self):
        try:
            check_runtime_clean()
        except SystemExit:
            self.fail("Release audit check failed")


if __name__ == "__main__":
    unittest.main()
