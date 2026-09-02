import unittest

from utils.input_normalization import normalize_digits


class InputNormalizationTests(unittest.TestCase):
    def test_persian_and_arabic_indic_digits_are_accepted(self):
        self.assertEqual(normalize_digits("۱۲۳۴۵۶"), "123456")
        self.assertEqual(normalize_digits("١٢٣٤٥٦"), "123456")

    def test_non_digit_text_is_unchanged(self):
        self.assertEqual(normalize_digits("yes-test"), "yes-test")


if __name__ == "__main__":
    unittest.main()
