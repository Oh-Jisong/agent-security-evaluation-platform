from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.schemas import AnalyzeRequest, RunLog
from app.services.logger import load_logs, save_log
from app.services.pipeline import run_pipeline
from app.services.scenario_loader import get_scenario_by_id, load_scenarios

app = FastAPI(title="Secure AI Agent Playground")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def serve_index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/scenarios")
def list_scenarios():
    return load_scenarios()


@app.get("/api/logs")
def list_logs():
    return load_logs()


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest):
    scenario = get_scenario_by_id(request.scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    updated_scenario = scenario.model_copy(
        update={
            "document_text": request.document_text,
            "user_prompt": request.user_prompt,
            "external_context": request.external_context,
        }
    )

    result = run_pipeline(updated_scenario, request.enabled_defenses)

    log = RunLog(
        run_id=result.run_id,
        scenario_id=result.scenario_id,
        attack_category=result.attack_category,
        attack_name=result.attack_name,
        enabled_defenses=result.applied_defenses,
        risk_score=result.risk_score,
        decision=result.decision,
        blocked_stage=result.blocked_stage,
        attack_success=result.attack_success,
        detection_success=result.detection_success,
        final_response=result.final_response,
        notes=result.notes,
    )
    save_log(log)

    return result

@app.get("/api/dashboard")
def dashboard_summary():
    logs = load_logs()

    total_runs = len(logs)
    blocked_runs = sum(1 for log in logs if log["decision"] == "Block")
    successful_attacks = sum(1 for log in logs if log["attack_success"] is True)

    attack_counts = {}
    blocked_stage_counts = {"Input": 0, "Context": 0, "Output": 0, "Action": 0, "-": 0}

    for log in logs:
        category = log["attack_category"]
        attack_counts[category] = attack_counts.get(category, 0) + 1

        stage = log["blocked_stage"] if log["blocked_stage"] is not None else "-"
        if stage not in blocked_stage_counts:
            blocked_stage_counts[stage] = 0
        blocked_stage_counts[stage] += 1

    return {
        "total_runs": total_runs,
        "blocked_runs": blocked_runs,
        "successful_attacks": successful_attacks,
        "attack_counts": attack_counts,
        "blocked_stage_counts": blocked_stage_counts,
    }