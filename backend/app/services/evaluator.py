from app.schemas import DecisionType


def decide_from_risk(risk_score: int) -> DecisionType:
    if risk_score >= 4:
        return "Block"
    if risk_score >= 2:
        return "Warn"
    return "Allow"