from src.analyzer import CyberMindAnalyzer


def print_report(result: dict):
    """Display the CYBERMIND-NLP analysis report."""

    print("\n" + "=" * 70)
    print("CYBERMIND-NLP")
    print("AI-BASED CYBERSECURITY TEXT ANALYZER")
    print("=" * 70)

    print("\nINPUT")
    print("-" * 70)
    print(result["input"])

    # ---------------------------------------------------------
    # NLP
    # ---------------------------------------------------------

    nlp = result["nlp"]

    print("\n" + "-" * 70)
    print("NLP ANALYSIS")
    print("-" * 70)

    print(f"\nTokens: {nlp['tokens']}")
    print(f"\nFiltered Tokens: {nlp['filtered_tokens']}")
    print(f"\nStemmed Tokens: {nlp['stemmed_tokens']}")
    print(f"\nLemmatized Tokens: {nlp['lemmatized_tokens']}")
    print(f"\nPOS Tags: {nlp['pos_tags']}")
    print(f"\nNamed Entities: {nlp['named_entities']}")
    print(f"\nExtracted URLs: {nlp['extracted_urls']}")

    # ---------------------------------------------------------
    # SENTIMENT
    # ---------------------------------------------------------

    sentiment = result["sentiment"]

    print("\n" + "-" * 70)
    print("SENTIMENT ANALYSIS")
    print("-" * 70)

    print(f"\nSentiment: {sentiment['sentiment']}")
    print(f"Compound Score: {sentiment['compound']}")
    print(f"Positive: {sentiment['positive']}")
    print(f"Negative: {sentiment['negative']}")
    print(f"Neutral: {sentiment['neutral']}")

    # ---------------------------------------------------------
    # KEYWORDS
    # ---------------------------------------------------------

    keywords = result["keywords"]

    print("\n" + "-" * 70)
    print("KEYWORD & SECURITY INDICATORS")
    print("-" * 70)

    print(
        f"\nImportant Keywords: "
        f"{keywords['keywords']}"
    )

    for category, matches in keywords[
        "security_indicators"
    ].items():
        print(f"{category}: {matches}")

    print(
        f"\nTotal Security Indicators: "
        f"{keywords['total_indicators']}"
    )

    # ---------------------------------------------------------
    # URL
    # ---------------------------------------------------------

    urls = result["urls"]

    print("\n" + "-" * 70)
    print("URL ANALYSIS")
    print("-" * 70)

    print(f"\nURLs Found: {urls['urls']}")

    for analysis in urls["analyses"]:

        print(f"\nURL: {analysis['url']}")
        print(f"Hostname: {analysis['hostname']}")
        print(f"Scheme: {analysis['scheme']}")
        print(
            f"Suspicious Terms: "
            f"{analysis['suspicious_terms']}"
        )
        print(
            f"Indicators: "
            f"{analysis['indicators']}"
        )

    # ---------------------------------------------------------
    # HEURISTIC
    # ---------------------------------------------------------

    heuristic = result["heuristic"]

    print("\n" + "-" * 70)
    print("HEURISTIC THREAT ANALYSIS")
    print("-" * 70)

    print(
        f"\nThreat Category: "
        f"{heuristic['threat_category']}"
    )

    print(
        f"Risk Score: "
        f"{heuristic['risk_score']}/100"
    )

    print(
        f"Risk Level: "
        f"{heuristic['risk_level']}"
    )

    # ---------------------------------------------------------
    # ML
    # ---------------------------------------------------------

    ml = result["machine_learning"]

    print("\n" + "-" * 70)
    print("MACHINE LEARNING CLASSIFICATION")
    print("-" * 70)

    print(
        f"\nPredicted Threat: "
        f"{ml['prediction']}"
    )

    print(
        f"Model Confidence: "
        f"{ml['confidence']:.4f}"
    )

    print("\nClass Probabilities:")

    for label, probability in ml[
        "probabilities"
    ].items():
        print(
            f"  {label}: "
            f"{probability:.4f}"
        )

    # ---------------------------------------------------------
    # FINAL
    # ---------------------------------------------------------

    final = result["final_assessment"]

    print("\n" + "=" * 70)
    print("FINAL CYBERSECURITY ASSESSMENT")
    print("=" * 70)

    print(
        f"\nFINAL THREAT: "
        f"{final['final_threat'].upper()}"
    )

    print(
        f"FINAL RISK SCORE: "
        f"{final['risk_score']}/100"
    )

    print(
        f"FINAL RISK LEVEL: "
        f"{final['risk_level']}"
    )

    print("\nDecision Reasons:")

    for reason in final["reasons"]:
        print(f"  ✓ {reason}")

    print("\n" + "=" * 70)


def main():
    analyzer = CyberMindAnalyzer()

    print("\n" + "=" * 70)
    print("CYBERMIND-NLP")
    print("Interactive Cybersecurity Text Analyzer")
    print("=" * 70)

    print(
        "\nEnter a message, email, SMS, or other text "
        "for analysis."
    )

    print(
        "Type 'exit' to close the application."
    )

    while True:

        print("\n" + "-" * 70)

        text = input(
            "\nEnter text: "
        ).strip()

        if text.lower() == "exit":
            print("\nExiting CYBERMIND-NLP.")
            break

        if not text:
            print(
                "\nPlease enter some text."
            )
            continue

        result = analyzer.analyze(text)

        print_report(result)


if __name__ == "__main__":
    main()