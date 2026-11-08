import unittest

from wordcount import count_words


class TestWordcount(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(count_words("a b a"), {"a": 2, "b": 1})

    def test_newlines_and_case(self):
        self.assertEqual(count_words("The cat\nthe  dog\n"), {"the": 2, "cat": 1, "dog": 1})


if __name__ == "__main__":
    unittest.main()
