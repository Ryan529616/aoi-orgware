import unittest

from slugify import slugify


class SlugifyTests(unittest.TestCase):
    def test_simple_words(self) -> None:
        self.assertEqual(slugify("AOI Orgware"), "aoi-orgware")

    def test_collapses_separators_and_punctuation(self) -> None:
        self.assertEqual(slugify("  AOI   Orgware!  "), "aoi-orgware")


if __name__ == "__main__":
    unittest.main()
