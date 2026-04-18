let scenarios = [];
let attackChart = null;
let stageChart = null;

async function loadScenarios() {
  const res = await fetch("/api/scenarios");
  scenarios = await res.json();

  const select = document.getElementById("scenarioSelect");
  select.innerHTML = "";

  scenarios.forEach((scenario) => {
    const option = document.createElement("option");
    option.value = scenario.scenario_id;
    option.textContent = `${scenario.scenario_id} | ${scenario.attack_category} | ${scenario.title}`;
    select.appendChild(option);
  });

  if (scenarios.length > 0) {
    renderScenario(scenarios[0].scenario_id);
  }

  select.addEventListener("change", (e) => {
    renderScenario(e.target.value);
  });
}

function renderScenario(scenarioId) {
  const scenario = scenarios.find((item) => item.scenario_id === scenarioId);
  if (!scenario) return;

  document.getElementById("documentText").value = scenario.document_text;
  document.getElementById("userPrompt").value = scenario.user_prompt;
  document.getElementById("externalContext").value = scenario.external_context;
}

function setBadge(elementId, value, type) {
  const el = document.getElementById(elementId);
  el.textContent = value;
  el.className = "badge";

  if (type === "decision") {
    if (value === "Allow") el.classList.add("allow");
    else if (value === "Warn") el.classList.add("warn");
    else if (value === "Block") el.classList.add("block");
  }

  if (type === "bool") {
    if (value === "Yes") el.classList.add("yes");
    else el.classList.add("no");
  }
}

async function loadLogs() {
  const res = await fetch("/api/logs");
  const logs = await res.json();

  const tbody = document.querySelector("#logTable tbody");
  tbody.innerHTML = "";

  logs.forEach((log) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${log.run_id}</td>
      <td>${log.scenario_id}</td>
      <td>${log.attack_category}<br>${log.attack_name}</td>
      <td>${log.enabled_defenses.join(", ")}</td>
      <td>${log.risk_score}</td>
      <td>${log.decision}</td>
      <td>${log.blocked_stage ?? "-"}</td>
      <td>${log.attack_success ? "Yes" : "No"}</td>
    `;
    tbody.appendChild(row);
  });
}

async function loadDashboard() {
  const res = await fetch("/api/dashboard");
  const data = await res.json();

  document.getElementById("totalRuns").textContent = data.total_runs;
  document.getElementById("blockedRuns").textContent = data.blocked_runs;
  document.getElementById("successfulAttacks").textContent = data.successful_attacks;

  renderAttackChart(data.attack_counts);
  renderStageChart(data.blocked_stage_counts);
}

function renderAttackChart(attackCounts) {
  const ctx = document.getElementById("attackChart").getContext("2d");
  if (attackChart) attackChart.destroy();

  attackChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: Object.keys(attackCounts),
      datasets: [
        {
          label: "Runs",
          data: Object.values(attackCounts)
        }
      ]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function renderStageChart(stageCounts) {
  const ctx = document.getElementById("stageChart").getContext("2d");
  if (stageChart) stageChart.destroy();

  stageChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: Object.keys(stageCounts),
      datasets: [
        {
          label: "Blocked Count",
          data: Object.values(stageCounts)
        }
      ]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false }
      }
    }
  });
}

async function runScenario() {
  const scenarioId = document.getElementById("scenarioSelect").value;
  const enabledDefenses = Array.from(
    document.querySelectorAll('input[type="checkbox"]:checked')
  ).map((checkbox) => checkbox.value);

  const documentText = document.getElementById("documentText").value;
  const userPrompt = document.getElementById("userPrompt").value;
  const externalContext = document.getElementById("externalContext").value;

  const res = await fetch("/api/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      scenario_id: scenarioId,
      enabled_defenses: enabledDefenses,
      document_text: documentText,
      user_prompt: userPrompt,
      external_context: externalContext,
    }),
  });

  const result = await res.json();

  document.getElementById("attackCategory").textContent = result.attack_category;
  document.getElementById("attackName").textContent = result.attack_name;
  document.getElementById("riskScore").textContent = result.risk_score;
  setBadge("decision", result.decision, "decision");
  document.getElementById("blockedStage").textContent = result.blocked_stage ?? "-";
  setBadge("attackSuccess", result.attack_success ? "Yes" : "No", "bool");
  setBadge("detectionSuccess", result.detection_success ? "Yes" : "No", "bool");
  document.getElementById("finalResponse").value = result.final_response;
  document.getElementById("notes").value = result.notes;

  await loadLogs();
  await loadDashboard();
}

document.getElementById("runBtn").addEventListener("click", runScenario);

loadScenarios();
loadLogs();
loadDashboard();