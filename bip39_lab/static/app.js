"use strict";

const $ = (id) => document.getElementById(id);
const token = document.querySelector('meta[name="lab-token"]').content;
const number = new Intl.NumberFormat("pt-BR");
const PERCENT_SCALE = 1_000_000n;
let current = {status: "idle"};
let renderedJob = null;
let lastSample = null;
let rates = [];
let alertedJob = null;
let audioContext = null;
let connected = false;
let busy = false;

function asBigInt(value) {
  if (typeof value === "bigint") return value;
  if (typeof value === "string" && /^-?\d+$/.test(value)) return BigInt(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  throw new TypeError("Valor inteiro inválido.");
}

function formatInteger(value) {
  const digits = asBigInt(value).toString();
  return digits.replace(/\B(?=(\d{3})+(?!\d))/g, ".");
}

function formatScaledInteger(value, digits) {
  const scaled = asBigInt(value);
  const divisor = 10n ** BigInt(digits);
  const whole = scaled / divisor;
  const fraction = (scaled % divisor).toString().padStart(digits, "0");
  return `${formatInteger(whole)},${fraction}`;
}

function progressScaled(stats) {
  if (stats.progress_scaled !== undefined && stats.progress_scaled !== null) {
    return asBigInt(stats.progress_scaled);
  }
  const total = asBigInt(stats.total_combinations);
  return total > 0n ? asBigInt(stats.attempts) * PERCENT_SCALE / total : 0n;
}

function decimalRational(value) {
  const text = String(value).toLowerCase();
  if (!/^[+]?\d+(?:\.\d+)?(?:e[+-]?\d+)?$/.test(text)) return null;
  const [coefficient, exponentText] = text.split("e");
  const [whole, fraction = ""] = coefficient.split(".");
  let numerator = BigInt(`${whole}${fraction}`);
  let decimalPlaces = fraction.length - (exponentText ? Number(exponentText) : 0);
  let denominator = 1n;
  if (decimalPlaces > 0) denominator = 10n ** BigInt(decimalPlaces);
  if (decimalPlaces < 0) numerator *= 10n ** BigInt(-decimalPlaces);
  return numerator > 0n ? {numerator, denominator} : null;
}

function roundedRatio(numerator, denominator, scale) {
  const scaled = numerator * scale;
  const quotient = scaled / denominator;
  return quotient + (scaled % denominator * 2n >= denominator ? 1n : 0n);
}

function etaDuration(stats) {
  const total = asBigInt(stats.total_combinations);
  const attempts = asBigInt(stats.attempts);
  const remaining = stats.remaining_combinations === undefined
    ? total - attempts : asBigInt(stats.remaining_combinations);
  if (remaining <= 0n) return "0 s";
  const rate = decimalRational(stats.rate);
  if (rate === null) return "—";

  const secondsNumerator = remaining * rate.denominator;
  const secondsDenominator = rate.numerator;
  let unit = "s";
  let unitSeconds = 1n;
  if (secondsNumerator >= secondsDenominator * 3600n) {
    unit = "h"; unitSeconds = 3600n;
  } else if (secondsNumerator >= secondsDenominator * 60n) {
    unit = "min"; unitSeconds = 60n;
  }
  const value = roundedRatio(secondsNumerator, secondsDenominator * unitSeconds, 10n);
  return `${formatScaledInteger(value, 1)} ${unit}`;
}

function text(id, value) {
  const node = $(id);
  if (node.textContent !== String(value)) node.textContent = value;
}

async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: {"X-Lab-Token": token, "Content-Type": "application/json"},
    cache: "no-store", credentials: "omit",
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(8000),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Não foi possível concluir a operação.");
  return result;
}

function error(message = "") {
  text("page-error", message);
  $("page-error").hidden = !message;
}

function duration(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds.toLocaleString("pt-BR", {maximumFractionDigits: 1})} s`;
  if (seconds < 3600) return `${(seconds / 60).toLocaleString("pt-BR", {maximumFractionDigits: 1})} min`;
  return `${(seconds / 3600).toLocaleString("pt-BR", {maximumFractionDigits: 1})} h`;
}

function renderWords(template, candidate = "") {
  const known = template.trim().split(/\s+/);
  const words = candidate ? candidate.split(" ") : known;
  for (let index = 0; index < 12; index++) {
    const slot = $("word-grid").children[index];
    const value = words[index] || "—";
    if (slot.lastChild.textContent !== value) slot.lastChild.textContent = value;
    slot.classList.toggle("unknown", known[index] === "?");
  }
}

function updateTemplatePreview() {
  if (["running", "stopping"].includes(current.status)) return;
  const template = $("template").value.trim();
  renderWords(template);
  const words = template ? template.split(/\s+/) : [];
  const unknown = words.filter((word) => word === "?").length;
  const validation = $("operation").value === "validate";
  if (validation) {
    text("template-help", words.length ? `${words.length}/12 palavras · ${unknown ? "remova o ? para validar" : "derivação direta de uma frase completa"}` : "Informe as 12 palavras, sem ?.");
    text("operation-help", "Apenas esta mnemonic será validada; nenhuma combinação será enumerada. O ritmo não altera a única tentativa.");
    text("total", words.length === 12 && unknown === 0 ? "1" : "—");
  } else {
    text("template-help", words.length ? `${words.length}/12 palavras · ${unknown}/11 posições desconhecidas` : "Substitua de uma a onze palavras por ?.");
    text("operation-help", "A busca limitada enumera somente as posições marcadas com ?. Até 11 são aceitas para o modelo matemático; espaços grandes são impraticáveis para concluir.");
    text("total", words.length === 12 && unknown > 0 && unknown <= 11 ? formatInteger(2048n ** BigInt(unknown)) : "—");
  }
}

function updateOperationPreview() {
  const validation = $("operation").value === "validate";
  $("template").placeholder = validation
    ? "Digite as 12 palavras completas da mnemonic BIP-39."
    : "Insira as palavras conhecidas e use ? nas posições desconhecidas.";
  $("start").innerHTML = validation ? "<span>✓</span> Validar mnemonic" : "<span>▶</span> Iniciar experimento";
  updateTemplatePreview();
}

function resetReadout() {
  for (const id of ["attempts", "valid", "rejected", "rate"]) text(id, "0");
  text("elapsed", "0,0 s"); text("eta", "—"); text("percentage", "0,0000%");
  $("progress").value = 0;
  text("sample-label", "AGUARDANDO INÍCIO"); text("checksum-state", "Aguardando");
  text("match-state", "Endereço exato"); text("derived-address", "Aguardando uma tentativa com checksum válido.");
  text("comparison-label", "A comparação acontece localmente.");
  $("stage-checksum").className = ""; $("stage-match").className = "";
  text("balance-amount", "—"); text("balance-status", "SEM CONSULTA");
  text("balance-detail", "Inicie um experimento para consultar o nó local.");
  $("rate-line").setAttribute("d", "M0 79H500");
  $("result").hidden = true;
  $("samples-body").replaceChildren();
  rates = []; lastSample = null; alertedJob = null;
}

function playAlert() {
  if (!$("sound").checked || !audioContext) return;
  for (const offset of [0, 0.3]) {
    const oscillator = audioContext.createOscillator();
    const gain = audioContext.createGain();
    oscillator.connect(gain); gain.connect(audioContext.destination);
    oscillator.frequency.value = offset ? 1046 : 784;
    const start = audioContext.currentTime + offset;
    gain.gain.setValueAtTime(0, start);
    gain.gain.linearRampToValueAtTime(0.09, start + 0.02);
    gain.gain.linearRampToValueAtTime(0, start + 0.22);
    oscillator.start(start); oscillator.stop(start + 0.23);
  }
}

function renderResult(state) {
  const terminal = ["found", "exhausted", "interrupted", "error"].includes(state.status);
  $("result").hidden = !terminal;
  $("reveal").hidden = !state.can_reveal;
  $("result").classList.toggle("funded", Boolean(state.funded_alert));
  if (!terminal) return;
  let title, description;
  if (state.funded_alert) {
    title = "Alvo encontrado com saldo de teste";
    description = "A mnemonic produziu o endereço exato. O nó confirmou saldo positivo após a correspondência.";
    if (alertedJob !== state.job_id) { alertedJob = state.job_id; playAlert(); }
  } else if (state.status === "found") {
    title = "Correspondência exata encontrada";
    const balance = state.balance;
    description = balance.status !== "verified" || !balance.after_match
      ? "A chave do alvo foi recuperada. Aguardando uma verificação atualizada do saldo."
      : "A chave do alvo foi recuperada. O saldo confirmado deste endereço é zero.";
  } else if (state.status === "exhausted") {
    title = "Espaço esgotado, sem correspondência";
    description = "Nenhuma combinação produziu o alvo. Confira as palavras conhecidas e a passphrase.";
  } else if (state.status === "interrupted") {
    title = "Experimento interrompido";
    description = "As tentativas concluídas estão preservadas na tela. Você pode iniciar um novo experimento.";
  } else {
    title = "Não foi possível concluir";
    description = state.error;
  }
  text("result-label", state.funded_alert ? "ALERTA · ALVO + SALDO CONFIRMADOS" : "RESULTADO DO EXPERIMENTO");
  text("result-title", title); text("result-description", description);
}

function render(state) {
  current = state;
  const running = ["running", "stopping"].includes(state.status);
  $("configuration").disabled = running || busy;
  $("start").disabled = running || busy || !connected;
  $("stop").disabled = state.status !== "running";
  $("generate").disabled = running || busy;
  $("example").disabled = running || busy;
  $("clear").disabled = busy;
  $("run-dot").className = `status-dot${running ? " working" : state.status === "found" ? " active" : ""}`;
  text("run-state", {idle: "Pronto para observar", running: "Experimento em andamento", stopping: "Interrompendo…", found: "Alvo encontrado", exhausted: "Espaço esgotado", interrupted: "Experimento interrompido", error: "Falha na execução"}[state.status]);
  if (state.status === "idle") {
    if (renderedJob !== null) { resetReadout(); hideKey(); }
    renderedJob = null;
    updateTemplatePreview();
    return;
  }
  if (renderedJob !== state.job_id) {
    resetReadout(); hideKey(); renderedJob = state.job_id;
    $("target").value = state.target; $("template").value = state.template;
    $("mode").value = state.mode; $("operation").value = state.operation || "limited";
  }
  const stats = state.stats;
  for (const [id, value] of [["attempts", stats.attempts], ["valid", stats.valid_mnemonics], ["rejected", stats.rejected_checksum], ["total", stats.total_combinations]]) text(id, formatInteger(value));
  text("elapsed", duration(stats.elapsed_seconds)); text("eta", etaDuration(stats));
  text("rate", number.format(Math.round(stats.rate)));
  const progress = progressScaled(stats);
  text("percentage", `${formatScaledInteger(progress, 4)}%`);
  $("progress").value = Number(progress) / 10_000;
  const sample = state.sample;
  renderWords(state.template, sample?.mnemonic);
  if (sample && lastSample !== sample.attempt) {
    lastSample = sample.attempt;
    text("sample-label", `AMOSTRA #${formatInteger(sample.attempt)}`);
    text("checksum-state", sample.checksum_valid ? "Válido · derivação feita" : "Descartado antes da seed");
    $("stage-checksum").className = sample.checksum_valid ? "passed" : "rejected";
    text(
      "derived-address",
      sample.checksum_valid && sample.last_derived_address
        ? sample.last_derived_address
        : "Aguardando uma tentativa com checksum válido.",
    );
    const matched = sample.checksum_valid && sample.last_derived_address === state.target;
    text("comparison-label", matched ? "Endereço derivado = endereço-alvo" : "Nenhuma correspondência nesta amostra.");
    text("match-state", matched ? "Correspondência exata" : "Endereço exato");
    $("stage-match").className = matched ? "passed" : "";
    rates.push(stats.rate); rates = rates.slice(-60);
    const ceiling = Math.max(60, ...rates) * 1.1;
    $("rate-line").setAttribute("d", rates.map((rate, index) => `${index ? "L" : "M"}${index * 500 / Math.max(1, rates.length - 1)} ${(76 - rate / ceiling * 68).toFixed(2)}`).join(" "));
    $("samples-body").replaceChildren(...state.samples.map((row) => {
      const tr = document.createElement("tr");
      for (const value of [formatInteger(row.attempt), row.valid ? "Válido" : "Inválido", row.valid ? "Seed → endereço → comparação" : "Descarte imediato"]) {
        const td = document.createElement("td"); td.textContent = value; tr.append(td);
      }
      return tr;
    }));
  }
  const balance = state.balance;
  text("balance-status", {verified: "NÓ CONECTADO", unavailable: "INDISPONÍVEL", checking: "CONSULTANDO"}[balance.status]);
  if (balance.status === "verified") {
    text("balance-amount", (balance.satoshis / 1e8).toLocaleString("pt-BR", {minimumFractionDigits: 8, maximumFractionDigits: 8}));
    text("balance-detail", `${formatInteger(balance.satoshis)} sat · bloco ${formatInteger(balance.height)} · verificado há ${duration(balance.age_seconds)}`);
  } else {
    text("balance-amount", "—");
    text("balance-detail", balance.error || "Conferindo o alvo no nó regtest local. Indisponível não significa saldo zero.");
  }
  document.querySelector(".balance-panel").classList.toggle("positive", balance.status === "verified" && balance.satoshis > 0);
  renderResult(state);
}

async function poll() {
  try {
    const state = await api("/api/state");
    connected = true;
    text("connection-text", "Painel local conectado"); $("connection-dot").className = "status-dot active";
    if (!busy) render(state);
  } catch (_) {
    connected = false; $("start").disabled = true;
    text("connection-text", "Conexão interrompida"); $("connection-dot").className = "status-dot";
    text("balance-status", "DESATUALIZADO"); text("balance-amount", "—");
    text("balance-detail", "Sem conexão com o painel. O último saldo não está confirmado.");
    $("result").classList.remove("funded");
    if (current.funded_alert) text("result-description", "A conexão foi interrompida. Aguarde uma nova verificação do saldo.");
  } finally { setTimeout(poll, 300); }
}

async function loadTarget(example) {
  busy = true; render(current); error();
  try {
    await api("/api/clear", {});
    const data = await api(example ? "/api/example" : "/api/generate", {passphrase: $("passphrase").value});
    if (example) $("passphrase").value = "";
    $("target").value = data.target; $("template").value = data.template;
    $("operation").value = "limited";
    current = {status: "idle"}; resetReadout(); renderedJob = null; updateOperationPreview();
    if (!example) { text("generated-phrase", data.mnemonic); $("generated-dialog").showModal(); }
  } catch (err) { error(err.message); }
  finally { busy = false; render(current); }
}

$("experiment-form").addEventListener("submit", async (event) => {
  event.preventDefault(); busy = true; render(current); error(); hideKey();
  if ($("sound").checked) {
    try { audioContext ||= new AudioContext(); await audioContext.resume(); } catch (_) { audioContext = null; }
  }
  try {
    await api("/api/start", {target: $("target").value.trim(), template: $("template").value.trim(), passphrase: $("passphrase").value, mode: $("mode").value, operation: $("operation").value});
    render(await api("/api/state"));
    if (matchMedia("(max-width: 850px)").matches) document.querySelector(".live-panel").scrollIntoView({behavior: "instant", block: "start"});
  } catch (err) { error(err.message); }
  finally { busy = false; render(current); }
});
$("stop").addEventListener("click", async () => { try { await api("/api/stop", {job_id: current.job_id}); } catch (err) { error(err.message); } });
$("clear").addEventListener("click", async () => {
  try { await api("/api/clear", {}); hideKey(); for (const id of ["passphrase", "target", "template"]) $(id).value = ""; error(); render({status: "idle"}); }
  catch (err) { error(err.message); }
});
$("generate").addEventListener("click", () => loadTarget(false));
$("example").addEventListener("click", () => loadTarget(true));
$("template").addEventListener("input", updateTemplatePreview);
$("operation").addEventListener("change", updateOperationPreview);
function closeGenerated() { $("generated-dialog").close(); text("generated-phrase", ""); }
$("close-generated").addEventListener("click", closeGenerated); $("use-generated").addEventListener("click", closeGenerated);
$("generated-dialog").addEventListener("close", () => text("generated-phrase", ""));
function hideKey() { $("key-dialog").close(); for (const id of ["private-key", "found-phrase", "found-address"]) text(id, ""); }
$("close-key").addEventListener("click", hideKey); $("hide-key").addEventListener("click", hideKey);
$("key-dialog").addEventListener("close", () => { for (const id of ["private-key", "found-phrase", "found-address"]) text(id, ""); });
$("reveal").addEventListener("click", async () => {
  const jobId = current.job_id;
  try {
    const result = await api("/api/reveal", {job_id: jobId});
    if (current.job_id !== jobId) return;
    text("private-key", result.private_key_hex); text("found-phrase", result.mnemonic); text("found-address", result.address);
    $("key-dialog").showModal();
  } catch (err) { error(err.message); }
});
for (let index = 0; index < 12; index++) {
  const slot = document.createElement("div"); slot.className = "word-slot";
  const position = document.createElement("span"); position.className = "position"; position.textContent = String(index + 1).padStart(2, "0");
  const word = document.createElement("span"); word.className = "word"; word.textContent = "—";
  slot.append(position, word); $("word-grid").append(slot);
}
updateOperationPreview();
poll();
