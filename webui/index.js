/* SPDX-License-Identifier: MIT */
/*
 * YukiZygisk - Static WebUI control surface.
 * Derived from KOWX712/ksu-webui-demo and Kagami's static WebUI.
 * License: MIT
 * Authors: KOWX712 and Anatdx
 */

import { DEFAULT_CONFIG, DEFAULT_STATUS, PATHS, api, getRuntimeMode } from "./api.js";
import { enableEdgeToEdge, toast as nativeToast } from "./assets/kernelsu.js";
import { LANGUAGE_OPTIONS, getNavigatorLanguage, translations } from "./i18n.js";

const TABS = [
  { id: "status", label: "nav.status", icon: "pulse" },
  { id: "settings", label: "nav.settings", icon: "tune" },
  { id: "about", label: "nav.about", icon: "info" },
];

const params = new URLSearchParams(globalThis.location?.search || "");
const requestedTab = params.get("tab");
const storedLanguage = localStorage.getItem("yukizygisk_language");

const state = {
  tab: TABS.some((tab) => tab.id === requestedTab) ? requestedTab : "status",
  language: LANGUAGE_OPTIONS.some((option) => option.value === storedLanguage)
    ? storedLanguage
    : getNavigatorLanguage(),
  theme: localStorage.getItem("yukizygisk_theme") || "system",
  runtimeMode: getRuntimeMode(),
  status: { ...DEFAULT_STATUS },
  config: { ...DEFAULT_CONFIG },
  system: { model: "…", android: "…", kernel: "…", selinux: "…" },
  meta: { name: "YukiZygisk", version: "dev", author: "Anatdx" },
  loading: true,
  refreshing: false,
  lastUpdated: "",
};

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function format(template, values = {}) {
  return String(template).replace(/\{(\w+)\}/g, (_match, key) => String(values[key] ?? `{${key}}`));
}

function t(key, fallback = key, values) {
  return format(translations[state.language]?.[key] ?? translations.en[key] ?? fallback, values);
}

function icon(name, className = "") {
  const paths = {
    pulse: '<path d="M3 12h4l2.2-6 4.1 12 2.3-6H21"/>',
    tune: '<path d="M4 7h10m4 0h2M4 17h2m4 0h10M14 4v6M8 14v6"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.2"/>',
    refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6"/>',
    theme: '<path d="M20 15.5A8.5 8.5 0 0 1 8.5 4 8.5 8.5 0 1 0 20 15.5Z"/>',
    reload: '<path d="M5 8a8 8 0 0 1 13.5-1.5L21 9M19 16A8 8 0 0 1 5.5 17.5L3 15"/><path d="M21 4v5h-5M3 20v-5h5"/>',
    external: '<path d="M14 4h6v6m0-6-9 9"/><path d="M18 13v6H5V6h6"/>',
  };
  return `<svg class="icon ${className}" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${paths[name] || paths.info}</svg>`;
}

function showToast(message, tone = "success") {
  nativeToast(message);
  const stack = document.getElementById("toast-stack");
  if (!stack)
    return;
  const item = document.createElement("div");
  item.className = `toast ${tone}`;
  item.textContent = message;
  stack.appendChild(item);
  requestAnimationFrame(() => item.classList.add("visible"));
  setTimeout(() => {
    item.classList.remove("visible");
    setTimeout(() => item.remove(), 220);
  }, 2600);
}

function applyTheme() {
  if (state.theme === "system")
    delete document.documentElement.dataset.theme;
  else
    document.documentElement.dataset.theme = state.theme;
}

function cycleTheme() {
  state.theme = state.theme === "system" ? "light" : state.theme === "light" ? "dark" : "system";
  localStorage.setItem("yukizygisk_theme", state.theme);
  applyTheme();
}

function statusPresentation() {
  if (state.status.safe_mode)
    return { tone: "warning", title: t("status.safeMode"), description: t("status.safeModeDesc") };
  if (state.status.available && state.status.kernel_alive)
    return { tone: "success", title: t("status.running"), description: t("status.runningDesc") };
  return {
    tone: "danger",
    title: t("status.unavailable"),
    description: state.status.error || t("status.unavailableDesc"),
  };
}

function rootImplLabel() {
  const labels = {
    "kernelsu-redirect": "root.ksuRedirect",
    kernelsu: "root.ksu",
    kernelpatch: "root.kernelPatch",
    unsupported: "root.unsupported",
    unknown: "common.unknown",
  };
  return t(labels[state.status.root_impl] || "common.unknown");
}

function policySourceLabel() {
  const labels = {
    kernel: "policy.kernel",
    "userspace-ksu-api": "policy.ksuUserspace",
    "userspace-apatch-config": "policy.apatchUserspace",
    unavailable: "common.unknown",
  };
  return t(labels[state.status.root_policy_source] || "common.unknown");
}

function stateBadge(value) {
  const tones = { injected: "success", failed: "danger", crashed: "warning", unsupported32: "muted" };
  return `<span class="badge ${tones[value] || "muted"}">${escapeHtml(t(`state.${value}`, value))}</span>`;
}

function emptyState(message) {
  return `<div class="empty-state">${escapeHtml(message)}</div>`;
}

function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function sectionHeader(title, description = "") {
  return `<div class="section-heading"><div><h2>${escapeHtml(title)}</h2>${description ? `<p>${escapeHtml(description)}</p>` : ""}</div></div>`;
}

function infoItem(label, value, code = false) {
  return `<div><dt>${escapeHtml(label)}</dt><dd>${code ? `<code>${escapeHtml(value)}</code>` : escapeHtml(value)}</dd></div>`;
}

function renderModuleCards() {
  const standard = state.status.modules || [];
  const native = state.status.native_modules || [];
  const cards = [
    ...standard.map((name) => ({ mark: "Z", name, detail: "Zygisk API", native: false, state: "injected" })),
    ...native.map((module) => ({
      mark: "N",
      name: module.id,
      detail: `${module.target_type}=${module.target}`,
      native: true,
      state: module.state,
    })),
  ];
  if (!cards.length)
    return emptyState(t("status.noModules"));
  return cards.map((item) => `<article class="module-card ${item.native ? "native" : ""}"><div class="module-mark">${item.mark}</div><div><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.detail)}</span></div>${stateBadge(item.state)}</article>`).join("");
}

function renderStatus() {
  const presentation = statusPresentation();
  const zygotes = state.status.zygote_monitor || [];
  const injections = state.status.native_injections || [];
  return `<div class="page-grid">
    <section class="hero-card ${presentation.tone}">
      <div class="hero-copy">
        <div class="eyebrow"><span class="status-dot"></span>${escapeHtml(t("status.injection"))} · ${escapeHtml(state.status.abi || "arm64-v8a")}</div>
        <h1>${escapeHtml(presentation.title)}</h1>
        <p>${escapeHtml(presentation.description)}</p>
        <div class="hero-meta"><span>${escapeHtml(t("status.lastUpdate"))} ${escapeHtml(state.lastUpdated || "—")}</span><span>PID ${escapeHtml(state.status.daemon_pid || "—")}</span></div>
      </div>
      <div class="hero-actions"><button class="button secondary" data-action="reload">${icon("reload")} ${escapeHtml(t("common.reload"))}</button></div>
    </section>

    ${state.status.safe_mode ? `<section class="alert-card warning"><strong>${escapeHtml(t("status.safeModeTitle"))}</strong><p>${escapeHtml(t("status.safeModeBody"))}</p><span>${escapeHtml(state.status.safe_mode_zygote)} · ${state.status.zygote_crashes} restart(s)</span></section>` : ""}

    <section class="metrics-grid">
      ${metric(t("status.injectCount"), Number(state.status.count || 0).toLocaleString())}
      ${metric(t("status.zygiskModules"), String(state.status.modules.length))}
      ${metric(t("status.nativeModules"), String(state.status.native_modules.length))}
      ${metric(t("status.zygotes"), String(zygotes.length))}
    </section>

    <section class="panel">
      ${sectionHeader(t("status.deviceInfo"))}
      <dl class="info-grid single">
        ${infoItem(t("status.device"), state.system.model)}
        ${infoItem(t("status.android"), state.system.android)}
        ${infoItem(t("status.kernel"), state.system.kernel, true)}
        ${infoItem(t("status.selinux"), state.system.selinux)}
      </dl>
    </section>

    <section class="panel">
      ${sectionHeader(t("status.runtimeInfo"), t("status.runtimeInfoDesc"))}
      <dl class="info-grid single">
        ${infoItem(t("status.rootImpl"), rootImplLabel())}
        ${infoItem(t("status.denylistSource"), policySourceLabel())}
        ${state.status.root_policy_source !== "kernel" ? infoItem(t("status.policyCache"), t(state.status.root_policy_cache_ready ? "policy.ready" : "policy.pending")) : ""}
        ${infoItem(t("common.abi"), state.status.abi || "—")}
        ${infoItem(t("status.daemonPid"), state.status.daemon_pid || "—")}
      </dl>
    </section>

    <section class="panel span-2">
      ${sectionHeader(t("status.zygoteMonitor"), t("status.zygoteMonitorDesc"))}
      <div class="data-list">${zygotes.length ? zygotes.map((item) => `<div class="data-row"><div class="identity"><strong>${escapeHtml(item.name)}</strong><span>PID ${escapeHtml(item.pid)}</span></div><code>${escapeHtml(item.abi)}</code>${stateBadge(item.state)}</div>`).join("") : emptyState(t("common.none"))}</div>
    </section>

    <section class="panel span-2">
      ${sectionHeader(t("status.modules"), t("status.modulesDesc"))}
      <div class="module-grid">${renderModuleCards()}</div>
    </section>

    <section class="panel span-2">
      ${sectionHeader(t("status.nativeInjections"), t("status.nativeInjectionsDesc"))}
      <div class="data-list">${injections.length ? injections.map((item) => `<div class="data-row native-row"><div class="identity"><strong>${escapeHtml(item.process)}</strong><span>${escapeHtml(item.module)} · ${escapeHtml(item.target_type)}=${escapeHtml(item.target)}</span></div><code>PID ${escapeHtml(item.pid)}</code>${stateBadge(item.state)}</div>`).join("") : emptyState(t("status.noNativeInjections"))}</div>
    </section>
  </div>`;
}

function switchCard(id, title, description, checked) {
  return `<label class="switch-card"><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(description)}</small></span><input id="${id}" type="checkbox" ${checked ? "checked" : ""}><span class="switch"><i></i></span></label>`;
}

function renderSettings() {
  return `<div class="page-grid">
    <section class="panel span-2">
      ${sectionHeader(t("settings.title"), t("settings.desc"))}
      <div class="switch-list">
        ${switchCard("setting-yukilinker", t("settings.yukilinker"), t("settings.yukilinkerDesc"), state.config.yukilinker)}
        <label class="select-card"><span><strong>${escapeHtml(t("settings.denylistMode"))}</strong><small>${escapeHtml(t("settings.denylistDesc", "", { root: rootImplLabel() }))}</small></span><select id="denylist-mode"><option value="0" ${state.config.denylist_mode === 0 ? "selected" : ""}>${escapeHtml(t("settings.denylistOff"))}</option><option value="1" ${state.config.denylist_mode === 1 ? "selected" : ""}>${escapeHtml(t("settings.denylistSkip"))}</option><option value="2" ${state.config.denylist_mode === 2 ? "selected" : ""}>${escapeHtml(t("settings.denylistRevert"))}</option></select></label>
        ${switchCard("setting-dmesg", t("settings.dmesg"), t("settings.dmesgDesc"), state.config.dmesg_log)}
      </div>
      <div class="panel-actions"><button class="button primary" data-action="save-config">${escapeHtml(t("common.save"))}</button></div>
    </section>

    <section class="panel span-2">
      ${sectionHeader(t("settings.policyTitle"), t("settings.policyDesc"))}
      <dl class="info-grid">
        ${infoItem(t("settings.policyOwner"), rootImplLabel())}
        ${infoItem(t("status.denylistSource"), policySourceLabel())}
        ${state.status.root_policy_source !== "kernel" ? infoItem(t("status.policyCache"), t(state.status.root_policy_cache_ready ? "policy.ready" : "policy.pending")) : ""}
        ${infoItem(t("settings.configPath"), PATHS.CONFIG, true)}
      </dl>
    </section>
  </div>`;
}

function renderAbout() {
  return `<div class="page-grid">
    <section class="about-hero span-2"><img src="./icon.svg" alt=""><div><h1>YukiZygisk</h1><p>${escapeHtml(t("about.description"))}</p><div class="chip-cloud"><span class="chip">${escapeHtml(state.meta.version)}</span><span class="chip">${escapeHtml(state.status.abi || "arm64-v8a")}</span><span class="chip">Apache-2.0 / GPL-2.0</span></div></div></section>
    <section class="panel">${sectionHeader(t("about.project"))}<p class="body-copy">${escapeHtml(t("about.projectBody"))}</p><dl class="info-grid single">${infoItem(t("about.version"), state.meta.version)}${infoItem(t("about.author"), state.meta.author)}</dl></section>
    <section class="panel">${sectionHeader(t("about.credits"))}<p class="body-copy">${escapeHtml(t("about.creditsBody"))}</p><a class="link-card" href="https://github.com/KOWX712/ksu-webui-demo">KOWX712/ksu-webui-demo${icon("external")}</a></section>
  </div>`;
}

function renderPage() {
  if (state.tab === "settings")
    return renderSettings();
  if (state.tab === "about")
    return renderAbout();
  return renderStatus();
}

function renderApp() {
  const root = document.getElementById("app");
  if (!root)
    return;
  if (state.loading) {
    root.innerHTML = `<div class="boot-panel"><img src="./icon.svg" alt="" width="52" height="52"><div><div class="boot-mark">YUKIZYGISK</div><p>${escapeHtml(t("common.loading"))}</p></div></div>`;
    return;
  }
  const activeTab = TABS.find((tab) => tab.id === state.tab) || TABS[0];
  root.className = "app-shell";
  root.innerHTML = `
    <header class="topbar">
      <div class="brand"><img src="./icon.svg" alt=""><div><strong>YukiZygisk</strong><span>${escapeHtml(t("app.subtitle"))}</span></div></div>
      <div class="topbar-actions">
        <span class="runtime-pill ${state.runtimeMode}">${escapeHtml(state.runtimeMode === "mock" ? t("common.mock") : t("common.live"))}</span>
        <select id="language-select" class="language-select" aria-label="Language">${LANGUAGE_OPTIONS.map((option) => `<option value="${option.value}" ${option.value === state.language ? "selected" : ""}>${escapeHtml(option.shortLabel)}</option>`).join("")}</select>
        <button class="icon-button" data-action="theme" aria-label="Theme">${icon("theme")}</button>
        <button class="icon-button ${state.refreshing ? "spinning" : ""}" data-action="refresh" aria-label="${escapeHtml(t("common.refresh"))}">${icon("refresh")}</button>
      </div>
    </header>
    <div class="workspace">
      <aside class="side-nav">${TABS.map((tab) => `<button class="nav-item ${tab.id === state.tab ? "active" : ""}" data-tab="${tab.id}">${icon(tab.icon)}<span>${escapeHtml(t(tab.label))}</span></button>`).join("")}</aside>
      <main class="page"><div class="page-titlebar"><div><span>${escapeHtml(t(activeTab.label))}</span><small>${escapeHtml(state.meta.version)}</small></div></div>${renderPage()}</main>
    </div>
    <nav class="bottom-nav">${TABS.map((tab) => `<button class="nav-item ${tab.id === state.tab ? "active" : ""}" data-tab="${tab.id}">${icon(tab.icon)}<span>${escapeHtml(t(tab.label))}</span></button>`).join("")}</nav>`;
}

function syncTabUrl() {
  const url = new URL(globalThis.location.href);
  url.searchParams.set("tab", state.tab);
  history.replaceState(null, "", url);
}

async function refreshAll({ includeConfig = true } = {}) {
  state.refreshing = true;
  renderApp();
  try {
    const requests = [api.getStatus(), api.getSystemInfo(), api.getModuleMeta()];
    if (includeConfig)
      requests.push(api.loadConfig());
    const [status, system, meta, config] = await Promise.all(requests);
    state.status = status;
    state.system = system;
    state.meta = meta;
    if (config)
      state.config = config;
    state.lastUpdated = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch (error) {
    state.status.error = error.message;
    showToast(error.message, "danger");
  } finally {
    state.refreshing = false;
    renderApp();
  }
}

function collectConfigControls() {
  const yukilinker = document.getElementById("setting-yukilinker");
  const dmesg = document.getElementById("setting-dmesg");
  const mode = document.getElementById("denylist-mode");
  if (yukilinker)
    state.config.yukilinker = yukilinker.checked;
  if (dmesg)
    state.config.dmesg_log = dmesg.checked;
  if (mode)
    state.config.denylist_mode = Number(mode.value);
}

async function saveConfig() {
  collectConfigControls();
  try {
    state.config = await api.saveConfig(state.config);
    state.status = await api.getStatus();
    showToast(t("settings.saved"));
    renderApp();
  } catch (error) {
    showToast(`${t("settings.saveFailed")}: ${error.message}`, "danger");
  }
}

async function reloadRuntime() {
  try {
    await api.reload();
    await refreshAll();
    showToast(t("settings.reloaded"));
  } catch (error) {
    showToast(`${t("settings.reloadFailed")}: ${error.message}`, "danger");
  }
}

document.addEventListener("click", async (event) => {
  const tab = event.target.closest("[data-tab]");
  if (tab) {
    state.tab = tab.dataset.tab;
    syncTabUrl();
    renderApp();
    return;
  }
  const action = event.target.closest("[data-action]")?.dataset.action;
  if (action === "refresh") await refreshAll();
  if (action === "reload") await reloadRuntime();
  if (action === "save-config") await saveConfig();
  if (action === "theme") cycleTheme();
});

document.addEventListener("change", (event) => {
  if (event.target.id === "language-select") {
    state.language = event.target.value;
    localStorage.setItem("yukizygisk_language", state.language);
    document.documentElement.lang = state.language;
    renderApp();
  }
});

async function bootstrap() {
  applyTheme();
  document.documentElement.lang = state.language;
  await enableEdgeToEdge(true).catch(() => false);
  try {
    const [status, config, system, meta] = await Promise.all([
      api.getStatus(),
      api.loadConfig(),
      api.getSystemInfo(),
      api.getModuleMeta(),
    ]);
    state.status = status;
    state.config = config;
    state.system = system;
    state.meta = meta;
    state.lastUpdated = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch (error) {
    state.status.error = error.message;
  } finally {
    state.loading = false;
    renderApp();
  }
}

bootstrap();
