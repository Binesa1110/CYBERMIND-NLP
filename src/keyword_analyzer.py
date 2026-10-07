import re

from sklearn.feature_extraction.text import TfidfVectorizer


class KeywordAnalyzer:
    """Extract important keywords and cybersecurity indicators."""

    SECURITY_PATTERNS = {
        "urgency": [
            "urgent",
            "immediately",
            "now",
            "hurry",
            "asap",
            "expires",
            "expired",
            "limited time",
            "act now",
            "within 24 hours",
            "immediate action",
        ],
        "credential_request": [
            "password",
            "username",
            "login",
            "credential",
            "otp",
            "pin",
            "passcode",
            "verification code",
            "verify account",
            "verification",
            "security code",
        ],
        "financial": [
            "bank",
            "payment",
            "money",
            "transfer",
            "credit card",
            "debit card",
            "account",
            "refund",
            "prize",
            "reward",
            "cash",
            "fee",
            "processing fee",
            "investment",
        ],
        "threat": [
            "suspended",
            "suspend",
            "blocked",
            "locked",
            "terminated",
            "legal action",
            "penalty",
            "fine",
            "warning",
            "restriction",
        ],
        "social_engineering": [
            "verify",
            "confirm",
            "click",
            "send",
            "share",
            "provide",
            "claim",
            "security",
            "identity",
            "complete verification",
        ],
        "scam": [
            "congratulations",
            "congratulation",
            "you won",
            "winner",
            "won",
            "cash prize",
            "prize",
            "reward",
            "claim your",
            "processing fee",
            "claim reward",
            "free money",
            "guaranteed",
            "lottery",
            "jackpot",
        ],
        "payment_request": [
            "pay",
            "payment",
            "processing fee",
            "send money",
            "transfer money",
            "pay the fee",
            "make a payment",
            "deposit",
        ],
    }

    URL_PATTERN = r"https?://[^\s]+|www\.[^\s]+"

    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            max_features=30,
        )

    def remove_urls(self, text: str) -> str:
        """Remove URLs before extracting keywords."""
        return re.sub(self.URL_PATTERN, " ", text)

    def extract_keywords(self, text: str) -> list[str]:
        """Extract important TF-IDF keywords."""
        cleaned_text = self.remove_urls(text)

        if not cleaned_text.strip():
            return []

        matrix = self.vectorizer.fit_transform([cleaned_text])
        feature_names = self.vectorizer.get_feature_names_out()

        if matrix.shape[1] == 0:
            return []

        scores = matrix.toarray()[0]

        keyword_scores = list(zip(feature_names, scores))
        keyword_scores.sort(
            key=lambda item: item[1],
            reverse=True,
        )

        return [
            keyword
            for keyword, score in keyword_scores
            if score > 0
        ]

    def detect_security_indicators(
        self,
        text: str,
    ) -> dict[str, list[str]]:
        """Detect cybersecurity-related indicators."""

        text_lower = self.remove_urls(text).lower()

        indicators = {}

        for category, patterns in self.SECURITY_PATTERNS.items():
            matches = []

            for pattern in patterns:
                if pattern.lower() in text_lower:
                    matches.append(pattern)

            if matches:
                indicators[category] = matches

        return indicators

    def analyze(self, text: str) -> dict:
        """Perform complete keyword and indicator analysis."""

        keywords = self.extract_keywords(text)

        security_indicators = self.detect_security_indicators(
            text
        )

        total_indicators = sum(
            len(matches)
            for matches in security_indicators.values()
        )

        return {
            "keywords": keywords,
            "security_indicators": security_indicators,
            "total_indicators": total_indicators,
        }