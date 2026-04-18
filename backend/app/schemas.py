from typing import List, Literal
from pydantic import BaseModel


AttackCategory = Literal[
    "Prompt Injection",
    "Jailbreak",
    "System Prompt Extraction",
    "Data Leakage",
    "Tool / Agent Misuse",
    "Output Manipulation",
    "Memory / Retrieval Poisoning",
    "Document / Multimodal Embedded Attacks",
]

PrimaryStage = Literal["Input", "Context", "Output", "Action"]

DefenseName = Literal[
    "Input Filter",
    "Context Sanitization",
    "Risk Scoring",
    "Output Validation",
    "Action Guard",
]

DecisionType = Literal["Allow", "Warn", "Block", "Rewrite", "Human Approval"]


class Scenario(BaseModel):
    scenario_id: str
    owner: str
    attack_category: AttackCategory
    attack_name: str
    primary_stage: PrimaryStage
    title: str
    description: str
    document_text: str
    user_prompt: str
    external_context: str
    expected_bad_behavior: str
    success_condition: str
    recommended_defenses: List[DefenseName]
    notes: str


class AnalyzeRequest(BaseModel):
    scenario_id: str
    enabled_defenses: List[DefenseName]
    document_text: str
    user_prompt: str
    external_context: str


class AnalyzeResponse(BaseModel):
    run_id: str
    scenario_id: str
    attack_category: str
    attack_name: str
    risk_score: int
    decision: DecisionType
    blocked_stage: str | None
    attack_success: bool
    detection_success: bool
    final_response: str
    applied_defenses: List[str]
    notes: str


class RunLog(BaseModel):
    run_id: str
    scenario_id: str
    attack_category: str
    attack_name: str
    enabled_defenses: List[str]
    risk_score: int
    decision: str
    blocked_stage: str | None
    attack_success: bool
    detection_success: bool
    final_response: str
    notes: str