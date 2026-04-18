import importlib


MODULE_PATHS = {
    "jisong": "app.services.defenses.jisong_defense",
    "jiwon": "app.services.defenses.jiwon_defense",
    "wana": "app.services.defenses.wana_defense",
    "fatin": "app.services.defenses.fatin_defense",
}


def get_defense_handlers(owner: str) -> dict:
    if owner not in MODULE_PATHS:
        raise ValueError(f"Unknown owner: {owner}")

    module_path = MODULE_PATHS[owner]

    try:
        module = importlib.import_module(module_path)
    except ModuleNotFoundError:
        raise ValueError(
            f"Defense module for owner '{owner}' is not implemented yet. "
            f"Expected module: {module_path}"
        )

    required_attrs = [
        "run_input_defense",
        "run_context_defense",
        "run_risk_scoring",
        "run_output_defense",
        "run_action_defense",
        "SUCCESS_TERMS",
    ]

    for attr in required_attrs:
        if not hasattr(module, attr):
            raise ValueError(
                f"Defense module '{module_path}' is missing required attribute: {attr}"
            )

    return {
        "input": module.run_input_defense,
        "context": module.run_context_defense,
        "risk": module.run_risk_scoring,
        "output": module.run_output_defense,
        "action": module.run_action_defense,
        "success_terms": module.SUCCESS_TERMS,
    }