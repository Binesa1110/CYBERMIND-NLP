from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.analyzer import CyberMindAnalyzer


app = FastAPI(
    title="CYBERMIND-NLP API",
    description=(
        "AI-based cybersecurity text analysis API "
        "using NLP, heuristic analysis, and machine learning."
    ),
    version="1.0.0",
)


# --------------------------------------------------
# Request Model
# --------------------------------------------------

class AnalysisRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        description="Message, email, SMS, or text to analyze.",
    )


# --------------------------------------------------
# Initialize Analyzer
# --------------------------------------------------

try:
    analyzer = CyberMindAnalyzer()
except Exception as error:
    analyzer = None
    initialization_error = str(error)


# --------------------------------------------------
# Health Check
# --------------------------------------------------

@app.get("/")
def root():
    return {
        "application": "CYBERMIND-NLP",
        "status": "running",
        "message": "Cybersecurity Text Analysis API",
    }


@app.get("/health")
def health_check():
    if analyzer is None:
        return {
            "status": "error",
            "analyzer": "not initialized",
            "error": initialization_error,
        }

    return {
        "status": "healthy",
        "analyzer": "ready",
    }


# --------------------------------------------------
# Analyze Endpoint
# --------------------------------------------------

@app.post("/analyze")
def analyze_text(request: AnalysisRequest):
    if analyzer is None:
        raise HTTPException(
            status_code=500,
            detail=(
                "CYBERMIND-NLP analyzer could not be initialized: "
                f"{initialization_error}"
            ),
        )

    try:
        result = analyzer.analyze(request.text)

        return {
            "status": "success",
            "result": result,
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(error)}",
        )