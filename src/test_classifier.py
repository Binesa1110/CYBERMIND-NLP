from pathlib import Path

from ml_classifier import ThreatClassifier


PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "cybermind_threat_classifier.joblib"
)


def main():
    print("\n" + "=" * 70)
    print("CYBERMIND-NLP - ML CLASSIFIER TEST")
    print("=" * 70)

    classifier = ThreatClassifier()

    print("\nLoading trained model...")
    classifier.load_model(str(MODEL_PATH))

    test_messages = [
        (
            "Your bank account will be locked today. "
            "Click this link to verify your password immediately."
        ),
        (
            "Congratulations! You have won a cash prize. "
            "Send your bank details to receive your reward."
        ),
        (
            "Please send me the OTP from your phone so I can "
            "complete the verification."
        ),
        (
            "The project meeting has been moved to tomorrow "
            "at 10 AM."
        ),
    ]

    print("\n" + "-" * 70)
    print("PREDICTIONS")
    print("-" * 70)

    for index, message in enumerate(test_messages, start=1):

        result = classifier.predict(message)

        print(f"\nTest Message {index}:")
        print(message)

        print(
            f"\nPrediction: "
            f"{result['prediction']}"
        )

        print(
            f"Confidence: "
            f"{result['confidence']:.4f}"
        )

        print("\nClass Probabilities:")

        for label, probability in result[
            "probabilities"
        ].items():
            print(
                f"  {label}: "
                f"{probability:.4f}"
            )

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()