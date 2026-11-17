from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

from ml_classifier import ThreatClassifier


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "test"
    / "unseen_messages.csv"
)

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "cybermind_threat_classifier.joblib"
)


def main():
    print("\n" + "=" * 70)
    print("CYBERMIND-NLP - UNSEEN DATASET EVALUATION")
    print("=" * 70)

    print("\nLoading unseen dataset...")

    dataset = pd.read_csv(DATASET_PATH)

    texts = dataset["text"].tolist()
    actual_labels = dataset["label"].tolist()

    classifier = ThreatClassifier()

    print("Loading trained model...")

    classifier.load_model(
        str(MODEL_PATH)
    )

    predictions = []

    for text in texts:
        result = classifier.predict(text)

        predictions.append(
            result["prediction"]
        )

    accuracy = accuracy_score(
        actual_labels,
        predictions,
    )

    correct_predictions = sum(
        actual == predicted
        for actual, predicted in zip(
            actual_labels,
            predictions,
        )
    )

    report = classification_report(
        actual_labels,
        predictions,
        zero_division=0,
    )

    matrix = confusion_matrix(
        actual_labels,
        predictions,
        labels=[
            "benign",
            "phishing",
            "scam",
            "social_engineering",
        ],
    )

    print("\n" + "-" * 70)
    print("UNSEEN DATASET RESULTS")
    print("-" * 70)

    print(
        f"\nTotal unseen samples: "
        f"{len(texts)}"
    )

    print(
        f"Correct predictions: "
        f"{correct_predictions}"
    )

    print(
        f"\nAccuracy: "
        f"{accuracy:.4f}"
    )

    print("\nClassification Report:")
    print(report)

    print("Confusion Matrix:")
    print(matrix)

    print("\n" + "-" * 70)
    print("DETAILED PREDICTIONS")
    print("-" * 70)

    for index, (
        text,
        actual,
        predicted,
    ) in enumerate(
        zip(
            texts,
            actual_labels,
            predictions,
        ),
        start=1,
    ):

        status = (
            "CORRECT"
            if actual == predicted
            else "INCORRECT"
        )

        print(f"\n[{index}] {status}")

        print(
            f"Text: {text}"
        )

        print(
            f"Actual: {actual}"
        )

        print(
            f"Predicted: {predicted}"
        )

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()