import json
from pathlib import Path
from typing import List, Optional

from app.schemas import Scenario


BASE_DIR = Path(__file__).resolve().parent.parent
SCENARIO_DIR = BASE_DIR / "data" / "scenarios"


def load_scenarios() -> List[Scenario]:
    scenarios: List[Scenario] = []

    for file_path in sorted(SCENARIO_DIR.glob("*_scenarios.json")):
        if file_path.name == "sample_scenarios.json":
            continue

        with open(file_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        for item in raw:
            scenarios.append(Scenario(**item))

    return scenarios


def get_scenario_by_id(scenario_id: str) -> Optional[Scenario]:
    for scenario in load_scenarios():
        if scenario.scenario_id == scenario_id:
            return scenario
    return None