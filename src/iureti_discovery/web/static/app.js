const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let enrichEnabled = false, enrichTimer = null;
let TYPES = {}, assets = [], selected = new Set(), expanded = new Set(), settings = null, pollTimer = null;

// Token de interfaz: solo hace falta cuando la sonda se expone fuera de 127.0.0.1 (se pasa por ?token=).
// Se guarda en sessionStorage y la URL se limpia para no dejarlo en el historial.
let UI_TOKEN = "";
try {
  const u = new URL(location.href);
  if (u.searchParams.get("token")) {
    UI_TOKEN = u.searchParams.get("token");
    sessionStorage.setItem("iureti_token", UI_TOKEN);
    u.searchParams.delete("token");
    history.replaceState(null, "", u.pathname + u.search);
  } else {
    UI_TOKEN = sessionStorage.getItem("iureti_token") || "";
  }
} catch (e) { /* sessionStorage puede fallar en modo privado */ }

function uiHeaders(extra = {}) {
  const h = { "X-Iureti-UI": "1", ...extra };     // cabecera propia: bloquea CSRF de otros sitios
  if (UI_TOKEN) h["X-Iureti-Token"] = UI_TOKEN;
  return h;
}
function withToken(url) {
  return UI_TOKEN ? url + (url.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(UI_TOKEN) : url;
}

function toast(msg, ms = 3500) {
  const t = $("#toast"); t.textContent = msg; t.style.display = "block";
  clearTimeout(t._h); t._h = setTimeout(() => (t.style.display = "none"), ms);
}
async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: uiHeaders({ "Content-Type": "application/json", ...(opts.headers || {}) }) });
  const data = r.headers.get("content-type")?.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error(data?.detail || data || r.statusText);
  return data;
}
const fmtDate = (s) => s ? new Date(s).toLocaleString("es-MX", { dateStyle: "short", timeStyle: "short" }) : "";
// Solo http(s): una URL javascript:/data: devuelta por la IA o anunciada por un equipo no debe ser clicable
const safeHref = (url) => /^https?:\/\//i.test(String(url || "")) ? esc(url) : "#";

document.querySelectorAll("nav button").forEach((b) => b.onclick = () => {
  document.querySelectorAll("nav button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll("section.tab").forEach((s) => s.classList.toggle("active", s.id === "tab-" + b.dataset.tab));
  if (b.dataset.tab === "assets") loadAssets();
});

// ---------- estado y escaneo ----------
async function loadStatus() {
  const st = await api("/api/status");
  $("#ver").textContent = "v" + st.version;
  if (!Object.keys(TYPES).length) {
    TYPES = st.device_types;
    $("#f-type").innerHTML += Object.entries(TYPES).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join("");
  }
  $("#networks").innerHTML = st.networks.map((n) =>
    `<span class="chip ${n.virtual ? "virtual" : ""}" data-net="${esc(n.network)}" title="${esc(n.interface)}${n.virtual ? " (virtual)" : ""}">${esc(n.network)} · ${esc(n.interface)}</span>`).join("");
  document.querySelectorAll("#networks .chip").forEach((c) => c.onclick = () => {
    const cur = $("#targets").value.trim();
    if (!cur.split(/[\s,]+/).includes(c.dataset.net)) $("#targets").value = (cur ? cur + "\n" : "") + c.dataset.net;
  });
  $("#oui-status").textContent = st.oui_available ? "Base OUI disponible." : "Base OUI no descargada: el fabricante por MAC no se mostrará.";
  renderStats(st.counts);
  enrichEnabled = st.enrich_enabled;
  renderService(st);
  if (!$("#or-models").children.length) $("#or-models").innerHTML = st.openrouter_models.map(([id, label]) => `<option value="${esc(id)}">${esc(label)}</option>`).join("");
  $("#enrich-all").disabled = !enrichEnabled || st.enrich.running;
  $("#enrich-all").title = enrichEnabled ? "Identifica productos en internet (IA + búsqueda web)" : "Actívala en Configuración › Búsqueda en internet";
  const ej = st.enrich;
  $("#enrich-progress").textContent = ej.running ? `Buscando en internet… ${ej.done}/${ej.total}`
    : ej.total ? `Búsqueda en internet: ${ej.done}/${ej.total} activos (${ej.cached} desde caché)${ej.errors.length ? ". Errores: " + [...new Set(ej.errors)].join("; ") : ""}.` : "";
  renderProgress(st.scan, st.last_summary);
  return st;
}
function renderService(st) {
  const a = st.agent;
  $("#service-card").style.display = a || st.managed ? "" : "none";
  if (a?.update_available) {
    $("#update-notice").style.display = "";
    $("#update-notice").innerHTML = `Hay una versión nueva de la sonda (<b>${esc(a.latest_version)}</b>; instalada ${esc(st.version)}). Actualiza con <span class="mono">sudo apt upgrade</span> o volviendo a correr el instalador.`;
  } else $("#update-notice").style.display = "none";
  if (!a) { $("#service-info").innerHTML = "La interfaz corre sin el agente (<span class='mono'>serve</span> sin <span class='mono'>--agent</span>): no hay heartbeat ni escaneos programados."; return; }
  const sch = st.schedule.interval_minutes ? `cada ${st.schedule.interval_minutes / 60} h${st.schedule.window ? " entre " + esc(st.schedule.window) : ""}` : "sin escaneos programados";
  const conn = a.connected ? `<span class="ok">conectada</span> · último contacto ${fmtDate(a.last_heartbeat)}`
    : a.error ? `<span class="warn">${esc(a.error)}</span>` : `<span class="muted">sin iurefficient configurado</span>`;
  const sync = st.last_sync?.at ? ` · último envío ${fmtDate(st.last_sync.at)}${st.last_sync.error ? ` <span class="err">(${esc(st.last_sync.error)})</span>` : ""}` : "";
  $("#service-info").innerHTML = `<div>iurefficient: ${conn}${st.managed ? " · <b>gestionada</b>" : ""}</div><div>Programación: ${sch}${sync}</div>`;
}
function renderStats(c) {
  $("#stats").innerHTML = `<div class="stat"><b>${c.total}</b>activos</div><div class="stat"><b>${c.unsynced}</b>sin enviar / con cambios</div>`;
}
function renderProgress(p, summary) {
  const pct = p.total ? Math.round((100 * p.done) / p.total) : (p.running ? 0 : 100);
  $("#scan-bar").style.width = (p.started_at ? pct : 0) + "%";
  $("#start-scan").disabled = p.running;
  $("#cancel-scan").disabled = !p.running;
  if (!p.started_at) { $("#scan-phase").textContent = "Sin escaneos en curso."; $("#scan-detail").textContent = ""; return; }
  if (p.running) {
    $("#scan-phase").innerHTML = `Fase: <b>${esc(p.phase)}</b> — ${p.done}/${p.total}`;
    $("#scan-detail").textContent = `Hosts vivos hasta ahora: ${p.alive}. Rangos: ${p.targets.join(", ")}`;
  } else if (p.error) {
    $("#scan-phase").innerHTML = `<span class="err">Error: ${esc(p.error)}</span>`;
  } else {
    $("#scan-phase").innerHTML = `<span class="ok">Escaneo ${esc(p.phase)}</span> (${fmtDate(p.finished_at)})`;
    if (summary && !summary.error) $("#scan-detail").textContent = `${p.alive} hosts vivos · ${summary.assets} activos · ${summary.new} nuevos.`;
  }
}
async function poll() {
  const st = await loadStatus();
  if (st.scan.running) { pollTimer = setTimeout(poll, 1000); }
  else { pollTimer = null; loadHistory(); if ($("#tab-assets").classList.contains("active")) loadAssets(); }
}
async function loadHistory() {
  const rows = await api("/api/scans");
  $("#scan-history").innerHTML = rows.map((r) => `<tr><td>${fmtDate(r.started_at)}</td><td class="mono">${esc(r.targets.join(", "))}</td>
    <td>${r.error ? `<span class="err">${esc(r.error)}</span>` : esc(r.phase)}</td><td>${r.alive ?? ""}</td><td>${r.new_assets ?? ""}</td></tr>`).join("")
    || `<tr><td colspan="5" class="muted">Sin escaneos.</td></tr>`;
}
$("#start-scan").onclick = async () => {
  const targets = $("#targets").value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
  if (!targets.length) return toast("Indica al menos un rango.");
  try { await api("/api/scans", { method: "POST", body: JSON.stringify({ targets, snmp: $("#use-snmp").checked }) }); if (!pollTimer) poll(); }
  catch (e) { toast(e.message); }
};
$("#cancel-scan").onclick = () => api("/api/scans/cancel", { method: "POST" });

// ---------- activos ----------
async function loadAssets() {
  assets = await api("/api/assets");
  const ids = new Set(assets.map((a) => a.id));
  selected = new Set([...selected].filter((i) => ids.has(i)));
  renderAssets();
  loadStatus();
}
function remoteCell(a) {
  if (!a.remote_status) return a.synced_at ? `<span class="ok">enviado</span>` : `<span class="muted">sin enviar</span>`;
  const labels = { matched: ["ok", "coincide"], created_pending: ["warn", "en bandeja"], ignored: ["muted", "ignorado"], rejected: ["err", "rechazado"], accepted: ["ok", "recibido"] };
  const [cls, txt] = labels[a.remote_status] || ["", a.remote_status];
  const stale = a.synced_at && a.synced_at < a.last_seen ? ` <span class="small muted" title="Hay datos más nuevos sin enviar">•</span>` : "";
  return `<span class="${cls}" title="${esc(a.remote_reason)}">${txt}</span>${stale}`;
}
function renderAssets() {
  const q = $("#q").value.trim().toLowerCase(), ft = $("#f-type").value;
  const rows = assets.filter((a) => (!ft || a.device_type === ft) &&
    (!q || [a.hostname, a.vendor, a.model, a.serial, a.os, ...a.ips, ...a.macs].join(" ").toLowerCase().includes(q)));
  $("#empty").style.display = assets.length ? "none" : "block";
  $("#assets").innerHTML = rows.map((a) => {
    const row = `<tr data-id="${a.id}">
      <td><input type="checkbox" class="sel" ${selected.has(a.id) ? "checked" : ""} style="width:auto"></td>
      <td class="mono"><a href="#" class="toggle">${esc(a.ips[0] || "")}</a>${a.ips.length > 1 ? ` <span class="muted">+${a.ips.length - 1}</span>` : ""}</td>
      <td>${esc(a.hostname)}</td>
      <td><span class="type">${esc(TYPES[a.device_type] || a.device_type)}</span> <span class="conf">${Math.round(a.confidence * 100)}%</span></td>
      <td>${thumb(a)}${esc(a.vendor)}${a.model ? `<br><span class="muted small">${esc(a.model)}</span>` : ""}</td>
      <td class="mono">${esc(a.serial)}</td>
      <td class="mono">${esc(a.macs[0] || "")}</td>
      <td class="mono small">${esc(a.open_ports.join(" "))}</td>
      <td class="small">${fmtDate(a.last_seen)}</td>
      <td class="small">${remoteCell(a)}</td></tr>`;
    if (!expanded.has(a.id)) return row;
    const s = a.attributes.snmp || {};
    return row + `<tr class="detail"><td></td><td colspan="9">
      ${productBlock(a)}
      ${localBlock(a)}
      <div><b>Huella:</b> <span class="mono">${esc(a.fingerprint)}</span> · <b>Fuentes:</b> ${esc(a.sources.join(", "))} · <b>Vivo por:</b> ${esc((a.attributes.alive_by || []).join(", "))}</div>
      <div><b>Clasificación:</b> ${esc(a.reasons.join("; ") || "sin indicios")}</div>
      <div><b>IPs:</b> <span class="mono">${esc(a.ips.join(", "))}</span> · <b>MACs:</b> <span class="mono">${esc(a.macs.join(", "))}</span></div>
      ${a.os ? `<div><b>SO / firmware:</b> ${esc(a.os)}</div>` : ""}
      ${s.sys_descr ? `<div><b>SNMP</b> (${esc(s.credential)}): ${esc(s.sys_descr)} · <span class="mono">${esc(s.sys_object_id)}</span>${s.sys_location ? " · Ubicación: " + esc(s.sys_location) : ""}${s.sys_contact ? " · Contacto: " + esc(s.sys_contact) : ""}</div>` : ""}
      <div class="muted">Primera vez: ${fmtDate(a.first_seen)}${a.synced_at ? " · Enviado: " + fmtDate(a.synced_at) : ""}${a.inventory_id ? " · ID inventario: " + esc(a.inventory_id) : ""}</div>
    </td></tr>`;
  }).join("");
  document.querySelectorAll("#assets .toggle").forEach((el) => el.onclick = (e) => {
    e.preventDefault(); const id = el.closest("tr").dataset.id;
    expanded.has(id) ? expanded.delete(id) : expanded.add(id); renderAssets();
  });
  document.querySelectorAll("#assets .enrich").forEach((el) => el.onclick = async () => {
    const force = el.textContent !== "Buscar en internet";
    el.disabled = true; el.textContent = "Buscando…";
    try {
      const r = await api(`/api/assets/${el.dataset.id}/enrich?force=${force}`, { method: "POST" });
      toast(r.cached ? "Resultado tomado de la caché (mismo producto ya consultado)." : "Producto identificado.");
      loadAssets();
    } catch (e) { toast(e.message, 6000); el.disabled = false; el.textContent = "Buscar en internet"; }
  });
  document.querySelectorAll("#assets .sel").forEach((el) => el.onchange = () => {
    const id = el.closest("tr").dataset.id; el.checked ? selected.add(id) : selected.delete(id); updateSel();
  });
  updateSel();
}
function imgSrc(a) {
  const e = a.attributes.enrichment || {};
  return e.image_file ? withToken(`/api/images/${e.image_file}`) : "";
}
function thumb(a) { const src = imgSrc(a); return src ? `<img class="thumb" src="${src}" alt="" loading="lazy">` : ""; }
function productBlock(a) {
  const e = a.attributes.enrichment;
  const btn = `<button class="btn enrich" data-id="${a.id}" ${enrichEnabled ? "" : "disabled title='Actívala en Configuración'"}>${e ? "Volver a buscar" : "Buscar en internet"}</button>`;
  if (!e) return `<div style="margin:4px 0 10px">${btn}</div>`;
  if (!e.identified) return `<div class="product"><div class="info"><b>No identificado en internet.</b> ${esc(e.notes)} ${btn}</div></div>`;
  const src = imgSrc(a);
  return `<div class="product">${src ? `<img src="${src}" alt="${esc(e.product_name)}">` : ""}
    <div class="info"><h3>${esc(e.product_name || e.model)}<span class="badge">confianza ${esc(e.confidence)}</span></h3>
      <div>${esc(e.description)}</div>
      ${e.specs?.length ? `<ul>${e.specs.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      <div class="small muted">${[e.release_year && "Lanzamiento: " + esc(e.release_year), e.support_status && "Soporte: " + esc(e.support_status)].filter(Boolean).join(" · ")}</div>
      <div class="small">${e.product_url ? `<a href="${safeHref(e.product_url)}" target="_blank" rel="noopener noreferrer">Ficha del producto</a> · ` : ""}<span class="muted">Consultado ${fmtDate(e.fetched_at)}${e.model_used || e.model_requested ? " con " + esc(e.model_used || e.model_requested) : ""}${e.cost_usd != null ? ` · US$ ${Number(e.cost_usd).toFixed(4)}` : ""}</span> ${btn}</div>
      ${e.notes ? `<div class="small muted">${esc(e.notes)}</div>` : ""}
    </div></div>`;
}
function localBlock(a) {
  const at = a.attributes, u = at.upnp || {}, h = at.http || {}, m = at.mdns || {}, nb = at.netbios || {};
  const lines = [];
  if (u.manufacturer || u.modelName) lines.push(`<b>UPnP:</b> ${esc([u.manufacturer, u.modelName, u.modelNumber].filter(Boolean).join(" · "))}${u.serialNumber ? ` · serie <span class="mono">${esc(u.serialNumber)}</span>${u.serialDecoded ? ` (${esc(u.serialDecoded)})` : ""}` : ""}`);
  if (h.title || h.server || h.realm || h.model_candidates) lines.push(`<b>Web:</b> ${esc([h.title, h.realm, h.server].filter(Boolean).join(" · "))}${h.model_candidates ? ` · posibles modelos: ${esc(h.model_candidates.join(", "))}` : ""}${h.url ? ` · <a href="${safeHref(h.url)}" target="_blank" rel="noopener noreferrer">abrir</a>` : ""}`);
  if (m.services?.length) lines.push(`<b>mDNS:</b> ${esc(m.host || "")} · ${esc(m.services.join(", "))}${at.announced_name ? ` · se anuncia como «${esc(at.announced_name)}»` : ""}`);
  if (nb.name) lines.push(`<b>NetBIOS:</b> ${esc(nb.name)}${nb.group ? " · grupo " + esc(nb.group) : ""}`);
  if (at.ttl) lines.push(`<b>TTL:</b> ${at.ttl} (${esc({unix: "Linux/Android/macOS/iOS", windows: "Windows", network: "equipo de red"}[at.os_family] || "")})`);
  return lines.map((l) => `<div>${l}</div>`).join("");
}
function updateSel() { $("#delete-sel").disabled = !selected.size; $("#delete-sel").textContent = selected.size ? `Olvidar ${selected.size}` : "Olvidar seleccionados"; }
$("#sel-all").onchange = (e) => { document.querySelectorAll("#assets .sel").forEach((el) => { el.checked = e.target.checked; const id = el.closest("tr").dataset.id; e.target.checked ? selected.add(id) : selected.delete(id); }); updateSel(); };
$("#q").oninput = renderAssets;
$("#f-type").onchange = renderAssets;
$("#delete-sel").onclick = async () => {
  const r = await api("/api/assets/delete", { method: "POST", body: JSON.stringify({ ids: [...selected] }) });
  toast(`${r.deleted} activos olvidados en la sonda (no afecta a iurefficient).`); selected.clear(); loadAssets();
};
$("#enrich-all").onclick = async () => {
  try {
    const r = await api("/api/enrich", { method: "POST" });
    if (!r.total) return toast("No hay activos pendientes con datos de producto para buscar.");
    const tick = async () => { const st = await loadStatus(); if (st.enrich.running) enrichTimer = setTimeout(tick, 1500); else loadAssets(); };
    tick();
  } catch (e) { toast(e.message, 6000); }
};
$("#export-csv").onclick = () => (location.href = withToken("/api/export.csv"));
$("#export-json").onclick = () => (location.href = withToken("/api/export.json"));
$("#sync").onclick = async () => {
  $("#sync").disabled = true;
  try {
    const r = await api("/api/sync", { method: "POST" });
    const detail = Object.entries(r.results).map(([k, v]) => `${v} ${k}`).join(", ");
    toast(`Enviados ${r.sent} activos en ${r.batches.length} lote(s)${detail ? ": " + detail : ""}.`, 6000);
    loadAssets();
  } catch (e) { toast(e.message, 6000); }
  finally { $("#sync").disabled = false; }
};

// ---------- configuración ----------
const SIMPLE = ["probe_id", "site", "api_url", "api_token", "concurrency", "tcp_timeout", "enrich_provider",
  "openrouter_api_key", "openrouter_model", "openrouter_web_engine", "anthropic_api_key", "anthropic_model"];
const BOOLS = ["use_ping", "resolve_dns", "use_mdns", "use_ssdp", "use_http", "use_netbios", "enrich_enabled", "auto_sync", "auto_enrich"];
async function loadSettings() {
  settings = await api("/api/settings");
  SIMPLE.forEach((k) => ($("#s-" + k).value = settings[k] ?? ""));
  $("#s-schedule_window").value = settings.schedule_window || "";
  $("#sched-hours").value = (settings.schedule_interval_minutes || 0) / 60;
  $("#sched-targets").textContent = (settings.targets || []).join(", ") || "—";
  const managed = !!settings.managed;
  ["#sched-hours", "#s-schedule_window"].forEach((sel) => ($(sel).disabled = managed));
  if (managed) $("#sched-note").innerHTML = "<b>Gestionada por iurefficient:</b> rangos y programación los define iurefficient (Inventario › Sondas).";
  $("#s-allowed_networks").value = (settings.allowed_networks || []).join(", ");
  BOOLS.forEach((k) => ($("#s-" + k).checked = !!settings[k]));
  if (!$("#targets").value && settings.targets.length) $("#targets").value = settings.targets.join("\n");
  renderCreds();
  showProvider();
}
function showProvider() {
  const prov = $("#s-enrich_provider").value;
  document.querySelectorAll(".prov").forEach((el) => (el.style.display = el.classList.contains("prov-" + prov) ? "" : "none"));
}
$("#s-enrich_provider").onchange = showProvider;
function credField(i, key, label, type = "text", opts = null) {
  const v = settings.snmp_credentials[i][key] ?? "";
  if (opts) return `<div><label>${label}</label><select data-i="${i}" data-k="${key}">${opts.map((o) => `<option ${o === v ? "selected" : ""}>${o}</option>`).join("")}</select></div>`;
  return `<div><label>${label}</label><input data-i="${i}" data-k="${key}" type="${type}" value="${esc(v)}" autocomplete="off"></div>`;
}
function renderCreds() {
  const list = settings.snmp_credentials;
  $("#creds").innerHTML = list.map((c, i) => `<div class="cred"><div class="row">
      ${credField(i, "name", `Nombre (SNMP ${c.version})`)}
      ${c.version === "2c" ? credField(i, "community", "Community", "password") : `
        ${credField(i, "user", "Usuario")}
        ${credField(i, "auth_protocol", "Autenticación", "text", ["SHA", "SHA256", "MD5"])}
        ${credField(i, "auth_key", "Clave auth", "password")}
        ${credField(i, "priv_protocol", "Cifrado", "text", ["AES", "AES256", "DES"])}
        ${credField(i, "priv_key", "Clave priv", "password")}`}
      <div style="flex:1 1 220px"><label>Subredes (CIDR, separadas por coma; vacío = todas)</label><input data-i="${i}" data-knet="1" type="text" value="${esc((c.networks || []).join(", "))}" placeholder="10.0.10.0/24" autocomplete="off"></div>
      <div style="flex:0 0 auto"><button class="btn danger" data-del="${i}">Quitar</button></div>
    </div>
    ${c.version === "2c" ? '<p class="small warn" style="margin:4px 0 0">La community SNMP v2c viaja sin cifrar. Restríngela a la VLAN de gestión y, si puedes, usa SNMP v3.</p>' : ""}
    </div>`).join("") || `<p class="muted small">Sin credenciales: no se consultará SNMP.</p>`;
  document.querySelectorAll("#creds [data-k]").forEach((el) => el.oninput = el.onchange = () => (list[el.dataset.i][el.dataset.k] = el.value));
  document.querySelectorAll("#creds [data-knet]").forEach((el) => el.oninput = el.onchange = () =>
    (list[el.dataset.i].networks = el.value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)));
  document.querySelectorAll("#creds [data-del]").forEach((el) => el.onclick = () => { list.splice(+el.dataset.del, 1); renderCreds(); });
  $("#snmp-hint").textContent = list.length ? `${list.length} credencial(es) SNMP configurada(s).` : "Sin credenciales SNMP (configúralas en Configuración).";
}
$("#add-v2").onclick = () => { settings.snmp_credentials.push({ name: "v2c-" + (settings.snmp_credentials.length + 1), version: "2c", community: "public" }); renderCreds(); };
$("#add-v3").onclick = () => { settings.snmp_credentials.push({ name: "v3-" + (settings.snmp_credentials.length + 1), version: "3", user: "", auth_protocol: "SHA", auth_key: "", priv_protocol: "AES", priv_key: "" }); renderCreds(); };
$("#save-settings").onclick = async () => {
  const body = { snmp_credentials: settings.snmp_credentials };
  SIMPLE.forEach((k) => (body[k] = $("#s-" + k).value.trim()));
  body.concurrency = parseInt(body.concurrency, 10) || 256;
  body.tcp_timeout = parseFloat(body.tcp_timeout) || 0.8;
  body.allowed_networks = $("#s-allowed_networks").value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  BOOLS.forEach((k) => (body[k] = $("#s-" + k).checked));
  if (!settings.managed) {
    body.schedule_window = $("#s-schedule_window").value.trim();
    body.schedule_interval_minutes = Math.round((parseFloat($("#sched-hours").value) || 0) * 60);
  }
  try { settings = await api("/api/settings", { method: "PUT", body: JSON.stringify(body) }); renderCreds(); toast("Configuración guardada."); loadStatus(); }
  catch (e) { toast(e.message); }
};
$("#oui-update").onclick = async () => {
  $("#oui-update").disabled = true; $("#oui-status").textContent = "Descargando…";
  try { const r = await api("/api/oui/update", { method: "POST" }); toast(`Base OUI actualizada: ${r.entries} fabricantes.`); }
  catch (e) { toast(e.message, 6000); }
  finally { $("#oui-update").disabled = false; loadStatus(); }
};

loadSettings().then(poll);
loadHistory();
