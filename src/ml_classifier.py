import joblib
import pandas as pd

from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


class ThreatClassifier:
    """Machine-learning classifier for cybersecurity text."""

    def __init__(self):
        self.model = Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(
                        lowercase=True,
                        stop_words="english",
                        ngram_range=(1, 2),
                        max_features=5000,
                    ),
                ),
                (
                    "classifier",
                    LogisticRegression(
                        max_iter=1000,
                        random_state=42,
                    ),
                ),
            ]
        )

    def load_dataset(self, dataset_path: str) -> pd.DataFrame:
        """Load and validate the cybersecurity dataset."""

        dataset = pd.read_csv(dataset_path)

        required_columns = {"text", "label"}

        if not required_columns.issubset(dataset.columns):
            raise ValueError(
                "Dataset must contain 'text' and 'label' columns."
            )

        dataset = dataset.dropna(
            subset=["text", "label"]
        )

        return dataset

    def train(
        self,
        dataset_path: str,
        test_size: float = 0.25,
    ) -> dict:
        """Train and evaluate the classifier."""

        dataset = self.load_dataset(dataset_path)

        X = dataset["text"]
        y = dataset["label"]

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=42,
            stratify=y,
        )

        self.model.fit(X_train, y_train)

        predictions = self.model.predict(X_test)

        accuracy = accuracy_score(
            y_test,
            predictions,
        )

        report = classification_report(
            y_test,
            predictions,
            zero_division=0,
        )

        matrix = confusion_matrix(
            y_test,
            predictions,
        )

        return {
            "accuracy": accuracy,
            "classification_report": report,
            "confusion_matrix": matrix,
            "training_samples": len(X_train),
            "testing_samples": len(X_test),
        }

    def predict(self, text: str) -> dict:
        """Predict the threat category of new text."""

        prediction = self.model.predict([text])[0]

        probabilities = self.model.predict_proba([text])[0]

        classes = self.model.classes_

        confidence = max(probabilities)

        probability_dict = {
            label: float(probability)
            for label, probability in zip(
                classes,
                probabilities,
            )
        }

        return {
            "prediction": prediction,
            "confidence": float(confidence),
            "probabilities": probability_dict,
        }

    def save_model(self, model_path: str) -> None:
        """Save the trained model to disk."""

        model_path = Path(model_path)

        model_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        joblib.dump(
            self.model,
            model_path,
        )

    def load_model(self, model_path: str) -> None:
        """Load a previously trained model."""

        self.model = joblib.load(model_path)