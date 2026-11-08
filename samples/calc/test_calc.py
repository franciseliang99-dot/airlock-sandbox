import unittest

from calc import add, mean


class TestCalc(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_mean(self):
        self.assertEqual(mean([1, 2, 3]), 2)

    def test_mean_empty(self):
        with self.assertRaises(ValueError):
            mean([])


if __name__ == "__main__":
    unittest.main()
