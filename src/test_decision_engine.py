from decision_engine import DecisionEngine


def main():
    engine = DecisionEngine()

    # Simulated results from the existing analyzers
    heuristic_result = {
        "threat_category": "SCAM",
        "risk_score": 50,
        "risk_level": "HIGH",
    }

    ml_result = {
        "prediction": "phishing",
        "confidence": 0.4759,
        "probabilities": {
            "benign": 0.1628,
            "phishing": 0.4759,
            "scam": 0.1696,
            "social_engineering": 0.1917,
        },
    }

    url_result = {
        "total_url_indicators": 1,
    }

    keyword_result = {
        "total_indicators": 8,
        "security_indicators": {
            "urgency": ["urgent", "immediately"],
            "credential_request": ["login"],
            "financial": ["bank", "account"],
            "threat": ["suspended"],
            "social_engineering": ["verify", "click"],
        },
    }

    result = engine.analyze(
        heuristic_result=heuristic_result,
        ml_result=ml_result,
        url_result=url_result,
        keyword_result=keyword_result,
    )

    print("\n" + "=" * 70)
    print("CYBERMIND-NLP - DECISION FUSION TEST")
    print("=" * 70)

    print("\nFINAL THREAT:")
    print(result["final_threat"])

    print("\nRISK SCORE:")
    print(f"{result['risk_score']}/100")

    print("\nRISK LEVEL:")
    print(result["risk_level"])

    print("\nCOMPONENT SCORES:")

    for label, score in result[
        "component_scores"
    ].items():
        print(
            f"  {label}: {score:.2f}"
        )

    print("\nREASONS:")

    for reason in result["reasons"]:
        print(f"  ✓ {reason}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()