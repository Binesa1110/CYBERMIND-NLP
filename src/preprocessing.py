import re

from nltk import ne_chunk, pos_tag
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer, WordNetLemmatizer
from nltk.tokenize import word_tokenize
from nltk.tree import Tree


class TextPreprocessor:
    """Preprocess textual content for NLP analysis."""

    URL_PATTERN = r"https?://[^\s]+|www\.[^\s]+"

    def __init__(self):
        self.stop_words = set(stopwords.words("english"))
        self.stemmer = PorterStemmer()
        self.lemmatizer = WordNetLemmatizer()

    def extract_urls(self, text: str) -> list[str]:
        """Extract URLs before NLP processing."""
        return re.findall(self.URL_PATTERN, text)

    def remove_urls(self, text: str) -> str:
        """Remove URLs from text before linguistic processing."""
        return re.sub(self.URL_PATTERN, " ", text)

    def clean_text(self, text: str) -> str:
        """Normalize textual content."""
        text = self.remove_urls(text)
        text = text.lower()

        # Preserve words and basic punctuation for tokenization.
        text = re.sub(r"\s+", " ", text)

        return text.strip()

    def tokenize(self, text: str) -> list[str]:
        """Tokenize cleaned text."""
        return word_tokenize(text)

    def remove_stopwords(
        self,
        tokens: list[str],
    ) -> list[str]:
        """Remove stopwords and non-alphabetic tokens."""

        return [
            token
            for token in tokens
            if token.isalpha()
            and token not in self.stop_words
        ]

    def stem(
        self,
        tokens: list[str],
    ) -> list[str]:
        """Apply Porter stemming."""

        return [
            self.stemmer.stem(token)
            for token in tokens
        ]

    def lemmatize(
        self,
        tokens: list[str],
    ) -> list[str]:
        """Apply WordNet lemmatization."""

        return [
            self.lemmatizer.lemmatize(token)
            for token in tokens
        ]

    def pos_tagging(
        self,
        tokens: list[str],
    ) -> list[tuple[str, str]]:
        """Assign Part-of-Speech tags."""

        return pos_tag(tokens)

    def named_entity_recognition(
        self,
        tokens: list[str],
    ) -> list[tuple[str, str]]:
        """Extract named entities."""

        tagged_tokens = pos_tag(tokens)
        tree = ne_chunk(tagged_tokens)

        entities = []

        for node in tree:
            if isinstance(node, Tree):
                entity_name = " ".join(
                    word
                    for word, tag in node.leaves()
                )

                entity_type = node.label()

                entities.append(
                    (entity_name, entity_type)
                )

        return entities

    def process(
        self,
        text: str,
    ) -> dict:
        """Run the complete NLP preprocessing pipeline."""

        urls = self.extract_urls(text)

        cleaned_text = self.clean_text(text)

        tokens = self.tokenize(cleaned_text)

        filtered_tokens = self.remove_stopwords(tokens)

        stemmed_tokens = self.stem(
            filtered_tokens
        )

        lemmatized_tokens = self.lemmatize(
            filtered_tokens
        )

        pos_tags = self.pos_tagging(
            filtered_tokens
        )

        named_entities = (
            self.named_entity_recognition(
                filtered_tokens
            )
        )

        return {
            "original_text": text,
            "extracted_urls": urls,
            "cleaned_text": cleaned_text,
            "tokens": tokens,
            "filtered_tokens": filtered_tokens,
            "stemmed_tokens": stemmed_tokens,
            "lemmatized_tokens": lemmatized_tokens,
            "pos_tags": pos_tags,
            "named_entities": named_entities,
        }