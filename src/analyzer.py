from pathlib import Path

from src.decision_engine import DecisionEngine
from src.keyword_analyzer import KeywordAnalyzer
from src.ml_classifier import ThreatClassifier
from src.preprocessing import TextPreprocessor
from src.sentiment import SentimentAnalyzer
from src.threat_analyzer import ThreatAnalyzer
from src.url_analyzer import URLAnalyzer


class CyberMindAnalyzer:
    """Complete CYBERMIND-NLP cybersecurity analysis engine."""

    def __init__(self):
        project_root = Path(__file__).resolve().parent.parent

        model_path = (
            project_root
            / "models"
            / "cybermind_threat_classifier.joblib"
        )

        self.processor = TextPreprocessor()
        self.sentiment_analyzer = SentimentAnalyzer()
        self.keyword_analyzer = KeywordAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.threat_analyzer = ThreatAnalyzer()
        self.ml_classifier = ThreatClassifier()
        self.decision_engine = DecisionEngine()

        self.ml_classifier.load_model(
            str(model_path)
        )

    def analyze(self, text: str) -> dict:
        """Run complete cybersecurity analysis."""

        nlp_result = self.processor.process(text)

        sentiment_result = (
            self.sentiment_analyzer.analyze(text)
        )

        keyword_result = (
            self.keyword_analyzer.analyze(text)
        )

        url_result = (
            self.url_analyzer.analyze(text)
        )

        heuristic_result = (
            self.threat_analyzer.analyze(
                security_indicators=(
                    keyword_result[
                        "security_indicators"
                    ]
                ),
                url_indicator_count=(
                    url_result[
                        "total_url_indicators"
                    ]
                ),
                sentiment_result=sentiment_result,
            )
        )

        ml_result = (
            self.ml_classifier.predict(text)
        )

        final_result = (
            self.decision_engine.analyze(
                heuristic_result=heuristic_result,
                ml_result=ml_result,
                url_result=url_result,
                keyword_result=keyword_result,
            )
        )

        return {
            "input": text,
            "nlp": nlp_result,
            "sentiment": sentiment_result,
            "keywords": keyword_result,
            "urls": url_result,
            "heuristic": heuristic_result,
            "machine_learning": ml_result,
            "final_assessment": final_result,
        }
        