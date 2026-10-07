class ThreatAnalyzer:
    """Heuristic cybersecurity threat analysis engine."""

    CATEGORY_WEIGHTS = {
        "PHISHING": {
            "credential_request": 15,
            "threat": 12,
            "urgency": 10,
            "social_engineering": 8,
        },
        "SCAM": {
            "scam": 20,
            "financial": 12,
            "payment_request": 15,
            "urgency": 8,
        },
        "SOCIAL_ENGINEERING": {
            "social_engineering": 15,
            "credential_request": 15,
            "urgency": 8,
        },
    }

    def calculate_category_score(
        self,
        category: str,
        security_indicators: dict[str, list[str]],
    ) -> int:
        """Calculate a heuristic score for one threat category."""

        weights = self.CATEGORY_WEIGHTS[category]

        score = 0

        for indicator_category, weight in weights.items():
            if indicator_category in security_indicators:
                matches = security_indicators[
                    indicator_category
                ]

                score += weight

                # Additional evidence from multiple matches.
                if len(matches) >= 2:
                    score += min(
                        5,
                        len(matches) - 1,
                    )

        return min(score, 60)

    def analyze(
        self,
        security_indicators: dict[str, list[str]],
        url_indicator_count: int,
        sentiment_result: dict,
    ) -> dict:
        """Perform heuristic threat analysis."""

        total_indicators = sum(
            len(matches)
            for matches in security_indicators.values()
        )

        category_scores = {
            category: self.calculate_category_score(
                category,
                security_indicators,
            )
            for category in self.CATEGORY_WEIGHTS
        }

        # URL evidence contributes to phishing risk.
        category_scores["PHISHING"] += min(
            url_indicator_count * 10,
            25,
        )

        category_scores["PHISHING"] = min(
            category_scores["PHISHING"],
            60,
        )

        # General evidence score.
        evidence_score = min(
            total_indicators * 5,
            30,
        )

        # Negative sentiment can provide supporting evidence,
        # but it is deliberately kept low-weight.
        sentiment_penalty = 0

        if (
            sentiment_result.get("sentiment") == "Negative"
            and sentiment_result.get("compound", 0) <= -0.2
        ):
            sentiment_penalty = 5

        best_category = max(
            category_scores,
            key=category_scores.get,
        )

        best_category_score = category_scores[best_category]

        risk_score = min(
            100,
            max(
                best_category_score,
                evidence_score + best_category_score // 2,
            ) + sentiment_penalty,
        )

        if risk_score == 0:
            threat_category = "BENIGN"
        elif best_category_score >= 20:
            threat_category = best_category
        else:
            threat_category = "BENIGN"

        # Risk level.
        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        reasons = []

        if total_indicators > 0:
            reasons.append(
                f"{total_indicators} security indicator(s) detected."
            )

        if url_indicator_count > 0:
            reasons.append(
                f"{url_indicator_count} suspicious URL indicator(s) detected."
            )

        if threat_category != "BENIGN":
            reasons.append(
                f"Heuristic classification: {threat_category}."
            )

        if sentiment_penalty > 0:
            reasons.append(
                "Negative sentiment provides additional supporting evidence."
            )

        return {
            "threat_category": threat_category,
            "risk_score": int(risk_score),
            "risk_level": risk_level,
            "category_scores": category_scores,
            "reasons": reasons,
        }