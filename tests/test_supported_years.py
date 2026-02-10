import unittest
from datetime import datetime

from balorcve.core import START_YEAR, get_supported_years


class TestSupportedYears(unittest.TestCase):
    def test_includes_current_year(self):
        current_year = datetime.now().year
        years = get_supported_years()
        self.assertIn(current_year, years)
        self.assertEqual(max(years), current_year)
        self.assertEqual(min(years), START_YEAR)

    def test_start_year_after_current_year(self):
        current_year = datetime.now().year
        years = get_supported_years(start_year=current_year + 1)
        self.assertEqual(years, [current_year])


if __name__ == "__main__":
    unittest.main()
