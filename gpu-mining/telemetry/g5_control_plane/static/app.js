"use strict";

const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
const $ = (id) => document.getElementById(id);

async function request(path, body) {
  const headers = {};
  const options = { method: body === undefined ? "GET" : "POST", headers, cache: "no-store" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = csrfToken;
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || "La solicitud fue rechazada.");
  return payload;
}

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}

function metric(label, value, detail) {
  const card = node("article", "metric-card");
  card.append(node("span", "metric-label", label), node("strong", "metric-value", value ?? "UNKNOWN"));
  if (detail) card.append(node("span", "metric-detail", detail));
  return card;
}

function renderSummary(state) {
  const budget = state.economics?.budget || {};
  const priceEstimate = state.economics?.hourly_price_estimate || {};
  $("summary").replaceChildren(
    metric("Estado económico", state.economics?.profit_status, "Ingresos o costos no verificados no se tratan como cero"),
    metric("Costo verificado", budget.verified_spend_usd == null ? "UNKNOWN" : `$${Number(budget.verified_spend_usd).toFixed(2)} USD`, `Límite duro $${state.economics?.hard_budget_cap_usd ?? 30} USD`),
    metric("Monitor", state.monitor?.implementation, `Política ${state.monitor?.policy_hash || "UNKNOWN"}`),
    metric("Tarifa horaria estimada", priceEstimate.usd_per_hour == null ? "UNKNOWN" : `$${Number(priceEstimate.usd_per_hour).toFixed(4)} USD/h`, "Estimación del operador; no es facturación verificada ni autoriza gasto"),
    metric("Kill switch", state.actions?.kill_switch_engaged ? "ENGAGED" : "DISENGAGED", "Las acciones reales siguen apagadas")
  );
}

function renderPolicy(state) {
  const root = $("policy");
  root.replaceChildren();
  const configuration = state.monitor?.configuration || {};
  root.append(node("p", "policy-hash mono", `SHA-256: ${state.monitor?.policy_hash || "UNKNOWN"}`));
  const floors = Array.isArray(configuration.gpu_floors_ths) ? configuration.gpu_floors_ths : [];
  const settings = configuration.settings || {};
  const list = node("div", "policy-list");
  for (const item of floors) {
    const row = node("div", "policy-row");
    row.append(
      node("strong", "", item.identity_key || "GPU identity UNKNOWN"),
      node("span", "", `${item.threshold_ths ?? "UNKNOWN"} TH/s`),
      node("span", "policy-origin", item.source || "UNKNOWN")
    );
    list.append(row);
  }
  for (const [name, item] of Object.entries(settings)) {
    const row = node("div", "policy-row");
    row.append(
      node("strong", "", name),
      node("span", "", item?.value ?? "UNKNOWN"),
      node("span", "policy-origin", item?.source || "UNKNOWN")
    );
    list.append(row);
  }
  root.append(list);
}

function renderGroups(state) {
  const root = $("groups");
  root.replaceChildren();
  for (const group of state.salad?.groups || []) {
    const card = node("article", "group-card");
    const title = node("div", "group-title");
    title.append(node("h3", "", group.container_group), node("span", "badge small", group.provider_observation_status));
    card.append(title, node("p", "muted", `Origen: ${group.data_classification}. Binding GPU: ${group.gpu_binding_status}. Facturación: ${group.billing_status}.`));
    const instances = Array.isArray(group.instances) ? group.instances : [];
    card.append(node("p", "instance-count", `${instances.length} instancia(s) observada(s)`));
    if (instances.length) {
      const list = node("ul", "instance-list");
      for (const item of instances) {
        const row = node("li", "instance-row");
        row.append(node("span", "mono", item.instance_id ?? item.id ?? "Instance ID UNKNOWN"));
        row.append(node("span", "muted", `Machine ${item.machine_id ?? "UNKNOWN"} · ${item.state ?? "UNKNOWN"}`));
        list.append(row);
      }
      card.append(list);
    } else {
      card.append(node("p", "empty-state", "Sin observaciones. El gate de lectura permanece bloqueado."));
    }
    const actions = node("div", "button-row");
    for (const [label, endpoint] of [["START grupo", "/api/actions/start"], ["STOP grupo", "/api/actions/stop"]]) {
      const button = node("button", "button secondary", label);
      button.disabled = state.actions?.live_actions_enabled !== true;
      button.title = "Acciones reales bloqueadas en esta versión offline";
      button.addEventListener("click", () => sendCommand(endpoint, { container_group: group.container_group }));
      actions.append(button);
    }
    card.append(actions);
    root.append(card);
  }
}

function renderDevices(state) {
  const root = $("devices");
  root.replaceChildren();
  const devices = state.monitor?.devices || [];
  if (!devices.length) {
    root.append(node("p", "empty-state", "ContinuousMonitor está listo; aún no hay muestras de GPU atribuibles."));
    return;
  }
  for (const gpu of devices) {
    const card = node("article", "device-card");
    card.append(node("div", "device-name", gpu.gpu_identity?.model || "GPU UNKNOWN"));
    card.append(node("div", "device-meta", `Machine ${gpu.machine_id || "UNKNOWN"} · Instance ${gpu.instance_id || "UNKNOWN"} · Track ${gpu.track_id || "UNKNOWN"}`));
    card.append(node("div", "device-stats", `Hashrate ${gpu.observed_window_hashrate_ths ?? "UNKNOWN"} TH/s · Floor ${gpu.gpu_floor_ths ?? "UNKNOWN"} TH/s · ${gpu.hash_health || "UNKNOWN"}`));
    card.append(node("div", "device-meta", `Binding ${gpu.binding?.binding_status || "UNKNOWN"} · Beneficio ${gpu.profit_status || "UNKNOWN"} · Calidad ${gpu.sample_quality?.coverage_ratio ?? "UNKNOWN"}`));
    const button = node("button", "button secondary", "REALLOCATE instancia");
    button.disabled = gpu.binding?.binding_status !== "VERIFIED" || state.actions?.live_actions_enabled !== true;
    button.title = gpu.binding?.reason || "Reallocation real deshabilitada";
    button.addEventListener("click", () => sendCommand("/api/actions/reallocate", { container_group: gpu.container_group_id, instance_id: gpu.instance_id, assignment_id: gpu.assignment_id, deterioration_id: gpu.deterioration_start_utc }));
    card.append(button);
    root.append(card);
  }
}

function renderFleets(state) {
  const root = $("fleets");
  root.replaceChildren();
  const fleets = Array.isArray(state.fleets) ? state.fleets : [];
  if (!fleets.length) {
    root.append(node("p", "empty-state", "Sin evidencia conciliada de flotilla. Ingreso, costo y margen permanecen UNKNOWN."));
    return;
  }
  for (const fleet of fleets) {
    const card = node("article", "group-card");
    const title = node("div", "group-title");
    title.append(node("h3", "", `Flotilla ${fleet.fleet_id || "UNKNOWN"}`), node("span", "badge small", fleet.profit_status || "UNKNOWN"));
    card.append(title, node("p", "muted", `Worker compartido: ${fleet.worker_id || "UNKNOWN"} · Conciliación: ${fleet.economic_reconciliation_status || "UNKNOWN"}`));
    const workerRevenue = fleet.worker_revenue || {};
    card.append(node("p", "instance-count", `BTC del worker: pool ${workerRevenue.pool_observed_btc ?? "UNKNOWN"} (${workerRevenue.pool_observed_status || "UNKNOWN"}) · acreditado ${workerRevenue.paid_btc ?? "UNKNOWN"} (${workerRevenue.paid_status || "UNKNOWN"})`));
    card.append(node("p", "muted", `Distribución de ingreso por máquina: ${workerRevenue.machine_level_distribution || "UNKNOWN"}`));
    const windows = Array.isArray(fleet.net_profit_by_compatible_window) ? fleet.net_profit_by_compatible_window : [];
    if (!windows.length) {
      card.append(node("p", "empty-state", "Beneficio y margen neto sobre costo: UNKNOWN; faltan ventanas compatibles de facturación e ingreso USD realizado."));
    } else {
      const list = node("ul", "instance-list");
      for (const window of windows) {
        const ratio = window.observed_net_profit_over_billed_cost_status === "VERIFIED"
          ? `${(Number(window.observed_net_profit_over_billed_cost_fraction) * 100).toFixed(2)}%`
          : "UNKNOWN";
        const row = node("li", "instance-row");
        row.append(node("span", "mono", `${window.window_start_utc || "?"} → ${window.window_end_utc || "?"}`));
        row.append(node("span", "muted", `Ingreso USD ${window.revenue_usd ?? "UNKNOWN"} · costo USD ${window.billing_cost_usd ?? "UNKNOWN"} · neto USD ${window.net_profit_usd ?? "UNKNOWN"} · neto/costo ${ratio}`));
        list.append(row);
      }
      card.append(node("p", "instance-count", "Margen neto observado sobre costo Salad verificado"), list);
    }
    const work = Array.isArray(fleet.observed_hashrate_by_coin_algorithm_window)
      ? fleet.observed_hashrate_by_coin_algorithm_window : [];
    if (work.length) {
      const details = work.map((item) => `${item.coin}/${item.algorithm}: ${item.observed_hashrate_ths} TH/s (${item.device_count} GPU)`).join(" · ");
      card.append(node("p", "device-meta", `Trabajo observado, agrupado por algoritmo: ${details}`));
    }
    root.append(card);
  }
}

function renderControls(state) {
  const root = $("controls");
  root.replaceChildren();
  const auto = node("button", "button secondary", state.actions?.auto_armed ? "Desarmar AUTO_REALLOCATE" : "Armar AUTO_REALLOCATE");
  auto.disabled = state.actions?.auto_reallocate !== true;
  auto.title = "AUTO_REALLOCATE está apagado por política";
  auto.addEventListener("click", () => sendCommand("/api/auto-reallocate", { armed: !state.actions?.auto_armed }));
  const kill = node("button", "button danger", "Activar kill switch");
  kill.addEventListener("click", () => sendCommand("/api/kill-switch", { engaged: true }));
  root.append(node("p", "muted", `Acciones Salad: ${state.actions?.live_actions_enabled ? "habilitadas" : "DISABLED"} · AUTO_REALLOCATE: OFF · Gasto: ${state.actions?.live_spend_authorized ? "autorizado" : "no autorizado"}`), auto, kill);
}

async function loadState() {
  try {
    const state = await request("/api/state");
    renderSummary(state);
    renderPolicy(state);
    renderGroups(state);
    renderDevices(state);
    renderFleets(state);
    renderControls(state);
  } catch (error) {
    showMessage(error.message);
  }
}

async function sendCommand(endpoint, body) {
  try {
    const result = await request(endpoint, body);
    showMessage(result.reason || result.status || "Solicitud procesada");
    await loadState();
  } catch (error) {
    showMessage(error.message);
  }
}

async function loadAudit() {
  try {
    const result = await request("/api/audit");
    const list = $("audit");
    list.replaceChildren();
    for (const item of [...(result.events || [])].reverse().slice(0, 30)) {
      const row = node("article", "audit-row");
      row.append(node("span", "mono", item.occurred_at_utc), node("strong", "", item.event_type), node("span", "muted", JSON.stringify(item.payload)));
      list.append(row);
    }
    if (!(result.events || []).length) list.append(node("p", "muted", "No hay eventos todavía."));
  } catch (error) {
    showMessage(error.message);
  }
}

function showMessage(message) {
  const box = node("div", "toast", message);
  document.body.append(box);
  window.setTimeout(() => box.remove(), 4500);
}

$("refresh").addEventListener("click", () => sendCommand("/api/refresh", {}));
$("load-audit").addEventListener("click", loadAudit);
loadState();
