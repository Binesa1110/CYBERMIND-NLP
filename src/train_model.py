from pathlib import Path

from ml_classifier import ThreatClassifier


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "cybersecurity_messages.csv"
)

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "cybermind_threat_classifier.joblib"
)


def main():
    print("\n" + "=" * 70)
    print("CYBERMIND-NLP - MODEL TRAINING")
    print("=" * 70)

    print("\nLoading dataset...")
    print(f"Dataset: {DATASET_PATH}")

    classifier = ThreatClassifier()

    results = classifier.train(
        dataset_path=str(DATASET_PATH),
        test_size=0.25,
    )

    print("\n" + "-" * 70)
    print("TRAINING RESULTS")
    print("-" * 70)

    print(
        f"\nTraining samples: "
        f"{results['training_samples']}"
    )

    print(
        f"Testing samples: "
        f"{results['testing_samples']}"
    )

    print(
        f"\nAccuracy: "
        f"{results['accuracy']:.4f}"
    )

    print("\nClassification Report:")
    print(results["classification_report"])

    print("\nConfusion Matrix:")
    print(results["confusion_matrix"])

    classifier.save_model(
        str(MODEL_PATH)
    )

    print("\n" + "-" * 70)
    print("MODEL SAVED")
    print("-" * 70)

    print(f"\nModel: {MODEL_PATH}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()