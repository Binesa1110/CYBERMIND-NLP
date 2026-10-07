from nltk.sentiment import SentimentIntensityAnalyzer


class SentimentAnalyzer:
    """Analyze sentiment of text using NLTK VADER."""

    def __init__(self):
        self.analyzer = SentimentIntensityAnalyzer()

    def analyze(self, text: str) -> dict:
        """Return sentiment scores and classification."""

        scores = self.analyzer.polarity_scores(text)

        compound_score = scores["compound"]

        if compound_score >= 0.05:
            sentiment = "Positive"
        elif compound_score <= -0.05:
            sentiment = "Negative"
        else:
            sentiment = "Neutral"

        return {
            "sentiment": sentiment,
            "compound": compound_score,
            "positive": scores["pos"],
            "negative": scores["neg"],
            "neutral": scores["neu"],
        }