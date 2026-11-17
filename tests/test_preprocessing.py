"""Tests for the CYBERMIND text preprocessing pipeline."""

import unittest

from src.preprocessing import TextPreprocessor


class TextPreprocessorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.processor = TextPreprocessor()

    def test_extract_urls(self):
        text = "Visit https://example.com/login or www.example.org now."

        self.assertEqual(
            self.processor.extract_urls(text),
            ["https://example.com/login", "www.example.org"],
        )

    def test_remove_urls(self):
        text = "Go to https://evil.example/verify immediately."

        cleaned = self.processor.remove_urls(text)

        self.assertNotIn("http", cleaned)
        self.assertIn("immediately", cleaned)

    def test_clean_text_lowercases_and_normalises_whitespace(self):
        cleaned = self.processor.clean_text(
            "  HELLO   https://example.com   WORLD  "
        )

        self.assertEqual(cleaned, "hello world")

    def test_tokenize(self):
        tokens = self.processor.tokenize(
            "Your account is locked."
        )

        self.assertIn("account", tokens)
        self.assertIn(".", tokens)

    def test_remove_stopwords_keeps_alphabetic_tokens_only(self):
        tokens = ["your", "account", "is", "locked", "!", "123"]

        filtered = self.processor.remove_stopwords(tokens)

        self.assertIn("account", filtered)
        self.assertIn("locked", filtered)
        self.assertNotIn("your", filtered)
        self.assertNotIn("is", filtered)
        self.assertNotIn("!", filtered)
        self.assertNotIn("123", filtered)

    def test_stemming(self):
        stemmed = self.processor.stem(["suspended", "blocked"])

        self.assertEqual(stemmed, ["suspend", "block"])

    def test_lemmatisation(self):
        lemmatised = self.processor.lemmatize(["accounts"])

        self.assertEqual(lemmatised, ["account"])

    def test_process_returns_expected_keys(self):
        result = self.processor.process(
            "Your bank account is suspended. Verify at https://bank.example now"
        )

        for key in (
            "original_text",
            "extracted_urls",
            "cleaned_text",
            "tokens",
            "filtered_tokens",
            "stemmed_tokens",
            "lemmatized_tokens",
            "pos_tags",
            "named_entities",
        ):
            self.assertIn(key, result)

        self.assertEqual(
            result["extracted_urls"],
            ["https://bank.example"],
        )
        self.assertIn("bank", result["filtered_tokens"])

    def test_process_handles_empty_text(self):
        result = self.processor.process("")

        self.assertEqual(result["tokens"], [])
        self.assertEqual(result["filtered_tokens"], [])
        self.assertEqual(result["named_entities"], [])


if __name__ == "__main__":
    unittest.main()
