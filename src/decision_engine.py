class DecisionEngine:
    """Combine heuristic and machine-learning threat analysis."""

    def analyze(
        self,
        heuristic_result: dict,
        ml_result: dict,
        url_result: dict,
        keyword_result: dict,
    ) -> dict:
        """Generate the final cybersecurity assessment."""

        ml_prediction = ml_result["prediction"]
        ml_confidence = ml_result["confidence"]

        heuristic_category = (
            heuristic_result["threat_category"]
        )

        heuristic_score = heuristic_result["risk_score"]

        url_indicators = url_result[
            "total_url_indicators"
        ]

        total_security_indicators = keyword_result[
            "total_indicators"
        ]

        # --------------------------------------------------
        # Determine final threat
        # --------------------------------------------------

        if (
            ml_prediction == "benign"
            and heuristic_category == "BENIGN"
            and total_security_indicators == 0
            and url_indicators == 0
        ):
            final_threat = "benign"

        elif ml_prediction != "benign":
            final_threat = ml_prediction

        elif heuristic_category != "BENIGN":
            final_threat = heuristic_category.lower()

        else:
            final_threat = "benign"

        # --------------------------------------------------
        # Calculate final risk
        # --------------------------------------------------

        # Completely clean benign messages should remain low risk.
        if (
            final_threat == "benign"
            and total_security_indicators == 0
            and url_indicators == 0
            and heuristic_category == "BENIGN"
        ):
            final_risk_score = 0

        else:
            ml_score = ml_confidence * 100

            # Equal contribution from heuristic evidence
            # and machine-learning confidence.
            final_risk_score = (
                heuristic_score * 0.5
                + ml_score * 0.5
            )

            # Additional URL evidence.
            if url_indicators > 0:
                final_risk_score += min(
                    url_indicators * 5,
                    15,
                )

            # Additional security evidence.
            if total_security_indicators >= 5:
                final_risk_score += 5

            final_risk_score = min(
                100,
                int(round(final_risk_score)),
            )

        # --------------------------------------------------
        # Risk level
        # --------------------------------------------------

        if final_risk_score >= 70:
            risk_level = "CRITICAL"
        elif final_risk_score >= 50:
            risk_level = "HIGH"
        elif final_risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # --------------------------------------------------
        # Explanation
        # --------------------------------------------------

        reasons = []

        if total_security_indicators > 0:
            reasons.append(
                f"{total_security_indicators} security "
                "indicator(s) detected."
            )

        if url_indicators > 0:
            reasons.append(
                f"{url_indicators} suspicious URL "
                "indicator(s) detected."
            )

        reasons.append(
            f"Machine-learning prediction: "
            f"{ml_prediction}."
        )

        reasons.append(
            f"ML confidence: {ml_confidence:.2f}."
        )

        if heuristic_category != "BENIGN":
            reasons.append(
                f"Heuristic classification: "
                f"{heuristic_category}."
            )

        else:
            reasons.append(
                "Heuristic classification: BENIGN."
            )

        return {
            "final_threat": final_threat,
            "risk_score": final_risk_score,
            "risk_level": risk_level,
            "reasons": reasons,
            "component_scores": {
                "heuristic": heuristic_score,
                "machine_learning": round(
                    ml_confidence * 100,
                    2,
                ),
                "url_indicators": url_indicators,
                "security_indicators": total_security_indicators,
            },
        }