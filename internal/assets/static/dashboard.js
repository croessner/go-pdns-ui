(function () {
  "use strict";

  function setCookie(name, value, maxAgeSeconds) {
    document.cookie = `${name}=${encodeURIComponent(value)}; path=/; max-age=${maxAgeSeconds}; samesite=lax`;
  }

  function getCookie(name) {
    const pattern = `; ${document.cookie}`;
    const parts = pattern.split(`; ${name}=`);
    if (parts.length < 2) return "";
    return decodeURIComponent(parts.pop().split(";").shift());
  }

  function bindCollapsePersistence(scope) {
    const rootNode = scope instanceof Element ? scope : document;
    const collapses = rootNode.querySelectorAll("details[data-collapse-cookie]");
    collapses.forEach((element) => {
      if (element.dataset.collapseBound === "1" || !element.id) return;
      const cookieName = `go-pdns-ui-collapse-${element.id}`;
      const saved = getCookie(cookieName);
      if (saved === "open") element.open = true;
      if (saved === "closed") element.open = false;
      element.addEventListener("toggle", () => {
        setCookie(cookieName, element.open ? "open" : "closed", 60 * 60 * 24 * 365);
      });
      element.dataset.collapseBound = "1";
    });
  }

  function decodeTXTValue(raw) {
    const trimmed = (raw || "").trim();
    if (trimmed.length >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
      try {
        return JSON.parse(trimmed);
      } catch (_) {
        return trimmed.slice(1, -1);
      }
    }
    return trimmed;
  }

  function encodeTXTValue(raw) {
    return JSON.stringify(raw || "");
  }

  function decodeGenericQuotedValue(raw) {
    const value = (raw || "").trim();
    if (value.length >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
      return decodeTXTValue(value);
    }
    return value;
  }

  function parseSRVValue(raw) {
    const fields = (raw || "").trim().split(/\s+/).filter(Boolean);
    if (fields.length !== 4) {
      return { priority: "10", weight: "0", port: "5060", target: "" };
    }
    return {
      priority: fields[0],
      weight: fields[1],
      port: fields[2],
      target: fields[3]
    };
  }

  function parseMXValue(raw) {
    const fields = (raw || "").trim().split(/\s+/).filter(Boolean);
    if (fields.length < 2) {
      return { priority: "10", target: "" };
    }
    return {
      priority: fields[0],
      target: fields.slice(1).join(" ")
    };
  }

  function parseSOAValue(raw) {
    const fields = (raw || "").trim().split(/\s+/).filter(Boolean);
    if (fields.length < 7) {
      return {
        mname: "",
        rname: "",
        serial: "",
        refresh: "",
        retry: "",
        expire: "",
        minimum: ""
      };
    }
    return {
      mname: fields[0],
      rname: fields[1],
      serial: fields[2],
      refresh: fields[3],
      retry: fields[4],
      expire: fields[5],
      minimum: fields[6]
    };
  }

  function parseCAAValue(raw) {
    const trimmed = (raw || "").trim();
    const matched = /^(\d+)\s+([A-Za-z0-9-]+)\s+(.+)$/.exec(trimmed);
    if (!matched) {
      return { flags: "0", tag: "issue", value: "" };
    }
    return {
      flags: matched[1],
      tag: matched[2],
      value: decodeGenericQuotedValue(matched[3])
    };
  }

  function parseTLSAValue(raw) {
    const fields = (raw || "").trim().split(/\s+/).filter(Boolean);
    if (fields.length < 4) {
      return {
        usage: "3",
        selector: "1",
        matchingType: "1",
        certData: ""
      };
    }
    return {
      usage: fields[0],
      selector: fields[1],
      matchingType: fields[2],
      certData: fields.slice(3).join("")
    };
  }

  function pad2(value) {
    return value.toString().padStart(2, "0");
  }

  function defaultSOAValues() {
    const now = new Date();
    const serial = `${now.getUTCFullYear()}${pad2(now.getUTCMonth() + 1)}${pad2(now.getUTCDate())}01`;
    return {
      mname: "ns1.example.org.",
      rname: "hostmaster.example.org.",
      serial,
      refresh: "7200",
      retry: "1800",
      expire: "1209600",
      minimum: "3600"
    };
  }

  function defaultCAAValues() {
    return {
      flags: "0",
      tag: "issue",
      value: "letsencrypt.org"
    };
  }

  function defaultTLSAValues() {
    return {
      usage: "3",
      selector: "1",
      matchingType: "1",
      certData: ""
    };
  }

  function defaultMXValues() {
    return {
      priority: "10",
      target: "mail.example.org."
    };
  }

  const recordFormContexts = new Map();
  let recordFormSeq = 0;

  function nextRecordFormID() {
    recordFormSeq += 1;
    return `record-form-${recordFormSeq}`;
  }

  function getContextFromForm(form) {
    const existingID = (form.dataset.recordFormId || "").trim();
    if (existingID !== "") {
      const existing = recordFormContexts.get(existingID);
      if (existing && existing.form === form) {
        return existing;
      }
    }

    const typeInput = form.querySelector("select[name='type']");
    const contentInput = form.querySelector("input[name='content']");
    if (!typeInput || !contentInput) {
      return null;
    }

    const formID = existingID || nextRecordFormID();
    form.dataset.recordFormId = formID;

    const context = {
      id: formID,
      form,
      typeInput,
      contentInput,
      oldNameInput: form.querySelector("input[name='old_name']"),
      oldTypeInput: form.querySelector("input[name='old_type']"),
      cancelEditButton: form.querySelector("[data-record-edit-cancel='1']"),
      dialogByType: {
        TXT: null,
        MX: null,
        SRV: null,
        SOA: null,
        CAA: null,
        TLSA: null
      }
    };

    const dialogRoot = form.parentElement || form;
    context.dialogByType.TXT = dialogRoot.querySelector("dialog[data-record-dialog='TXT']");
    context.dialogByType.MX = dialogRoot.querySelector("dialog[data-record-dialog='MX']");
    context.dialogByType.SRV = dialogRoot.querySelector("dialog[data-record-dialog='SRV']");
    context.dialogByType.SOA = dialogRoot.querySelector("dialog[data-record-dialog='SOA']");
    context.dialogByType.CAA = dialogRoot.querySelector("dialog[data-record-dialog='CAA']");
    context.dialogByType.TLSA = dialogRoot.querySelector("dialog[data-record-dialog='TLSA']");

    Object.values(context.dialogByType).forEach((dialog) => bindDialogCloseBehavior(dialog));
    recordFormContexts.set(formID, context);

    const autoOpenDialog = (form.dataset.autoOpenRecordDialog || "").toUpperCase();
    const currentScrollY = window.scrollY;
    if (autoOpenDialog !== "" && openDialogByType(context, autoOpenDialog)) {
      requestAnimationFrame(() => {
        window.scrollTo(window.scrollX, currentScrollY);
      });
    }

    return context;
  }

  function ensureRecordFormContexts(scope) {
    const rootNode = scope instanceof Element ? scope : document;
    const forms = rootNode.querySelectorAll("form[data-record-form]");
    forms.forEach((form) => {
      getContextFromForm(form);
    });
  }

  function contextIsEditing(context) {
    const oldName = context.oldNameInput ? context.oldNameInput.value.trim() : "";
    const oldType = context.oldTypeInput ? context.oldTypeInput.value.trim() : "";
    return oldName !== "" && oldType !== "";
  }

  function requestRecordSubmit(context) {
    if (typeof context.form.requestSubmit === "function") {
      context.form.requestSubmit();
      return;
    }
    context.form.submit();
  }

  function triggerRecordEditCancel(context) {
    if (context.cancelEditButton && !context.cancelEditButton.disabled) {
      context.cancelEditButton.click();
    }
  }

  function bindDialogCloseBehavior(dialog) {
    if (!dialog || dialog.dataset.recordDialogCloseBound === "1") return;

    dialog.addEventListener("close", () => {
      const wasApplied = dialog.dataset.recordDialogApplied === "1";
      const openedInEditMode = dialog.dataset.recordDialogOpenedInEditMode === "1";
      dialog.dataset.recordDialogApplied = "0";
      dialog.dataset.recordDialogOpenedInEditMode = "0";

      if (!wasApplied || !openedInEditMode) {
        return;
      }

      const formID = (dialog.dataset.recordDialogFormId || "").trim();
      if (formID === "") return;

      const context = recordFormContexts.get(formID);
      if (!context) return;

      triggerRecordEditCancel(context);
    });

    dialog.dataset.recordDialogCloseBound = "1";
  }

  function markDialogOpening(context, dialog) {
    if (!dialog) return;
    dialog.dataset.recordDialogApplied = "0";
    dialog.dataset.recordDialogOpenedInEditMode = contextIsEditing(context) ? "1" : "0";
    dialog.dataset.recordDialogFormId = context.id;
  }

  function openTXTDialog(context) {
    const dialog = context.dialogByType.TXT;
    if (!dialog) return false;

    context.typeInput.value = "TXT";
    markDialogOpening(context, dialog);

    const txtInput = dialog.querySelector("[data-txt-dialog-input]");
    if (txtInput) {
      txtInput.value = decodeTXTValue(context.contentInput.value);
    }

    dialog.showModal();
    return true;
  }

  function openSRVDialog(context) {
    const dialog = context.dialogByType.SRV;
    if (!dialog) return false;

    context.typeInput.value = "SRV";
    markDialogOpening(context, dialog);

    const parsed = parseSRVValue(context.contentInput.value);
    const priorityInput = dialog.querySelector("[data-srv-priority]");
    const weightInput = dialog.querySelector("[data-srv-weight]");
    const portInput = dialog.querySelector("[data-srv-port]");
    const targetInput = dialog.querySelector("[data-srv-target]");

    if (priorityInput) priorityInput.value = parsed.priority;
    if (weightInput) weightInput.value = parsed.weight;
    if (portInput) portInput.value = parsed.port;
    if (targetInput) targetInput.value = parsed.target;

    dialog.showModal();
    return true;
  }

  function openMXDialog(context) {
    const dialog = context.dialogByType.MX;
    if (!dialog) return false;

    context.typeInput.value = "MX";
    markDialogOpening(context, dialog);

    const parsed = parseMXValue(context.contentInput.value);
    const defaults = defaultMXValues();
    const priorityInput = dialog.querySelector("[data-mx-priority]");
    const targetInput = dialog.querySelector("[data-mx-target]");

    if (priorityInput) priorityInput.value = parsed.priority || defaults.priority;
    if (targetInput) targetInput.value = parsed.target || defaults.target;

    dialog.showModal();
    return true;
  }

  function openSOADialog(context) {
    const dialog = context.dialogByType.SOA;
    if (!dialog) return false;

    context.typeInput.value = "SOA";
    markDialogOpening(context, dialog);

    const parsed = parseSOAValue(context.contentInput.value);
    const defaults = defaultSOAValues();
    const mnameInput = dialog.querySelector("[data-soa-mname]");
    const rnameInput = dialog.querySelector("[data-soa-rname]");
    const serialInput = dialog.querySelector("[data-soa-serial]");
    const refreshInput = dialog.querySelector("[data-soa-refresh]");
    const retryInput = dialog.querySelector("[data-soa-retry]");
    const expireInput = dialog.querySelector("[data-soa-expire]");
    const minimumInput = dialog.querySelector("[data-soa-minimum]");

    if (mnameInput) mnameInput.placeholder = defaults.mname;
    if (rnameInput) rnameInput.placeholder = defaults.rname;
    if (serialInput) serialInput.placeholder = defaults.serial;
    if (refreshInput) refreshInput.placeholder = defaults.refresh;
    if (retryInput) retryInput.placeholder = defaults.retry;
    if (expireInput) expireInput.placeholder = defaults.expire;
    if (minimumInput) minimumInput.placeholder = defaults.minimum;

    if (mnameInput) mnameInput.value = parsed.mname;
    if (rnameInput) rnameInput.value = parsed.rname;
    if (serialInput) serialInput.value = parsed.serial;
    if (refreshInput) refreshInput.value = parsed.refresh;
    if (retryInput) retryInput.value = parsed.retry;
    if (expireInput) expireInput.value = parsed.expire;
    if (minimumInput) minimumInput.value = parsed.minimum;

    dialog.showModal();
    return true;
  }

  function openCAADialog(context) {
    const dialog = context.dialogByType.CAA;
    if (!dialog) return false;

    context.typeInput.value = "CAA";
    markDialogOpening(context, dialog);

    const parsed = parseCAAValue(context.contentInput.value);
    const defaults = defaultCAAValues();
    const flagsInput = dialog.querySelector("[data-caa-flags]");
    const tagInput = dialog.querySelector("[data-caa-tag]");
    const valueInput = dialog.querySelector("[data-caa-value]");

    if (flagsInput) flagsInput.value = parsed.flags || defaults.flags;
    if (tagInput) tagInput.value = parsed.tag || defaults.tag;
    if (valueInput) valueInput.value = parsed.value || defaults.value;

    dialog.showModal();
    return true;
  }

  function openTLSADialog(context) {
    const dialog = context.dialogByType.TLSA;
    if (!dialog) return false;

    context.typeInput.value = "TLSA";
    markDialogOpening(context, dialog);

    const parsed = parseTLSAValue(context.contentInput.value);
    const defaults = defaultTLSAValues();
    const usageInput = dialog.querySelector("[data-tlsa-usage]");
    const selectorInput = dialog.querySelector("[data-tlsa-selector]");
    const matchingTypeInput = dialog.querySelector("[data-tlsa-matching-type]");
    const certDataInput = dialog.querySelector("[data-tlsa-cert-data]");

    if (usageInput) usageInput.value = parsed.usage || defaults.usage;
    if (selectorInput) selectorInput.value = parsed.selector || defaults.selector;
    if (matchingTypeInput) matchingTypeInput.value = parsed.matchingType || defaults.matchingType;
    if (certDataInput) certDataInput.value = parsed.certData || defaults.certData;

    dialog.showModal();
    return true;
  }

  function openDialogByType(context, type) {
    switch ((type || "").trim().toUpperCase()) {
      case "TXT":
        return openTXTDialog(context);
      case "MX":
        return openMXDialog(context);
      case "SRV":
        return openSRVDialog(context);
      case "SOA":
        return openSOADialog(context);
      case "CAA":
        return openCAADialog(context);
      case "TLSA":
        return openTLSADialog(context);
      default:
        return false;
    }
  }

  function applyRecordDialogValues(dialog, context) {
    const type = (dialog.dataset.recordDialog || "").trim().toUpperCase();

    switch (type) {
      case "TXT": {
        const txtInput = dialog.querySelector("[data-txt-dialog-input]");
        context.contentInput.value = encodeTXTValue(txtInput ? txtInput.value : "");
        break;
      }
      case "MX": {
        const defaults = defaultMXValues();
        const priorityInput = dialog.querySelector("[data-mx-priority]");
        const targetInput = dialog.querySelector("[data-mx-target]");
        const priority = priorityInput ? (priorityInput.value.trim() || defaults.priority) : defaults.priority;
        const target = targetInput ? (targetInput.value.trim() || defaults.target) : defaults.target;
        context.contentInput.value = `${priority} ${target}`.trim();
        break;
      }
      case "SRV": {
        const priorityInput = dialog.querySelector("[data-srv-priority]");
        const weightInput = dialog.querySelector("[data-srv-weight]");
        const portInput = dialog.querySelector("[data-srv-port]");
        const targetInput = dialog.querySelector("[data-srv-target]");
        const priority = priorityInput ? priorityInput.value.trim() : "";
        const weight = weightInput ? weightInput.value.trim() : "";
        const port = portInput ? portInput.value.trim() : "";
        const target = targetInput ? targetInput.value.trim() : "";
        context.contentInput.value = `${priority} ${weight} ${port} ${target}`.trim();
        break;
      }
      case "SOA": {
        const defaults = defaultSOAValues();
        const mnameInput = dialog.querySelector("[data-soa-mname]");
        const rnameInput = dialog.querySelector("[data-soa-rname]");
        const serialInput = dialog.querySelector("[data-soa-serial]");
        const refreshInput = dialog.querySelector("[data-soa-refresh]");
        const retryInput = dialog.querySelector("[data-soa-retry]");
        const expireInput = dialog.querySelector("[data-soa-expire]");
        const minimumInput = dialog.querySelector("[data-soa-minimum]");
        const mname = mnameInput ? (mnameInput.value.trim() || defaults.mname) : defaults.mname;
        const rname = rnameInput ? (rnameInput.value.trim() || defaults.rname) : defaults.rname;
        const serial = serialInput ? (serialInput.value.trim() || defaults.serial) : defaults.serial;
        const refresh = refreshInput ? (refreshInput.value.trim() || defaults.refresh) : defaults.refresh;
        const retry = retryInput ? (retryInput.value.trim() || defaults.retry) : defaults.retry;
        const expire = expireInput ? (expireInput.value.trim() || defaults.expire) : defaults.expire;
        const minimum = minimumInput ? (minimumInput.value.trim() || defaults.minimum) : defaults.minimum;
        context.contentInput.value = `${mname} ${rname} ${serial} ${refresh} ${retry} ${expire} ${minimum}`.trim();
        break;
      }
      case "CAA": {
        const defaults = defaultCAAValues();
        const flagsInput = dialog.querySelector("[data-caa-flags]");
        const tagInput = dialog.querySelector("[data-caa-tag]");
        const valueInput = dialog.querySelector("[data-caa-value]");
        const flags = flagsInput ? (flagsInput.value.trim() || defaults.flags) : defaults.flags;
        const tag = tagInput ? (tagInput.value.trim() || defaults.tag) : defaults.tag;
        const value = valueInput ? (valueInput.value.trim() || defaults.value) : defaults.value;
        context.contentInput.value = `${flags} ${tag} ${encodeTXTValue(value)}`.trim();
        break;
      }
      case "TLSA": {
        const defaults = defaultTLSAValues();
        const usageInput = dialog.querySelector("[data-tlsa-usage]");
        const selectorInput = dialog.querySelector("[data-tlsa-selector]");
        const matchingTypeInput = dialog.querySelector("[data-tlsa-matching-type]");
        const certDataInput = dialog.querySelector("[data-tlsa-cert-data]");
        const usage = usageInput ? (usageInput.value.trim() || defaults.usage) : defaults.usage;
        const selector = selectorInput ? (selectorInput.value.trim() || defaults.selector) : defaults.selector;
        const matchingType = matchingTypeInput ? (matchingTypeInput.value.trim() || defaults.matchingType) : defaults.matchingType;
        const certData = certDataInput ? certDataInput.value.replace(/\s+/g, "").trim() : "";
        context.contentInput.value = `${usage} ${selector} ${matchingType} ${certData || defaults.certData}`.trim();
        break;
      }
      default:
        return;
    }

    dialog.dataset.recordDialogApplied = "1";
    dialog.close();

    if (contextIsEditing(context)) {
      requestRecordSubmit(context);
    }
  }

  const root = document.documentElement;
  const scrollTopButton = document.getElementById("scroll-top");
  const confirmDialog = document.getElementById("confirm-action-modal");
  const confirmDialogTitle = document.getElementById("confirm-action-title");
  const confirmDialogMessage = document.getElementById("confirm-action-message");
  const confirmDialogDefaultTitle = confirmDialogTitle ? confirmDialogTitle.textContent.trim() : "";
  const themeController = window.__goPDNSUITheme || null;
  const allThemes = new Set(["light", "dark"]);

  let pendingConfirmIssueRequest = null;
  let preservedScrollY = null;

  function applyTheme(theme) {
    if (themeController && typeof themeController.applyTheme === "function") {
      return themeController.applyTheme(theme);
    }

    const resolvedTheme = allThemes.has(theme) ? theme : "light";
    root.setAttribute("data-theme", resolvedTheme);
    root.style.colorScheme = resolvedTheme;

    try {
      localStorage.setItem("go-pdns-ui-theme", resolvedTheme);
    } catch (_) {
      // Ignore storage failures (private mode/restrictions).
    }

    return resolvedTheme;
  }

  function updateScrollTopButtonVisibility() {
    if (!scrollTopButton) return;
    scrollTopButton.classList.remove("opacity-0", "pointer-events-none");
    scrollTopButton.classList.add("opacity-90");
  }

  function setActiveZoneSelection(activeSource) {
    document.querySelectorAll("[data-zone-select='1']").forEach((zoneButton) => {
      zoneButton.classList.remove("btn-primary");
      zoneButton.setAttribute("aria-current", "false");
    });

    if (!activeSource) return;
    activeSource.classList.add("btn-primary");
    activeSource.setAttribute("aria-current", "true");
  }

  if (scrollTopButton) {
    window.addEventListener("scroll", updateScrollTopButtonVisibility, { passive: true });
    updateScrollTopButtonVisibility();
  }

  if (confirmDialog) {
    confirmDialog.addEventListener("close", () => {
      pendingConfirmIssueRequest = null;
    });
  }

  document.body.addEventListener("click", (event) => {
    const confirmAcceptButton = event.target.closest("#confirm-action-accept");
    if (confirmAcceptButton) {
      if (!pendingConfirmIssueRequest) {
        if (confirmDialog) confirmDialog.close();
        return;
      }

      const issueRequest = pendingConfirmIssueRequest;
      pendingConfirmIssueRequest = null;
      issueRequest(true);
      if (confirmDialog) confirmDialog.close();
      return;
    }

    const modalTrigger = event.target.closest("[data-open-modal-id]");
    if (modalTrigger) {
      const modalID = (modalTrigger.dataset.openModalId || "").trim();
      if (modalID !== "") {
        const modal = document.getElementById(modalID);
        if (modal && typeof modal.showModal === "function") {
          modal.showModal();
          const autofocusField = modal.querySelector("[data-modal-autofocus='1']");
          if (autofocusField && typeof autofocusField.focus === "function") {
            requestAnimationFrame(() => autofocusField.focus());
          }
        }
      }
      return;
    }

    const scrollTopTarget = event.target.closest("#scroll-top");
    if (scrollTopTarget) {
      window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }

    const themeToggle = event.target.closest("#theme-toggle");
    if (themeToggle) {
      const current = root.getAttribute("data-theme") || "light";
      const next = current === "dark" ? "light" : "dark";
      applyTheme(next);
      return;
    }

    const applyButton = event.target.closest("[data-txt-dialog-apply], [data-mx-dialog-apply], [data-srv-dialog-apply], [data-soa-dialog-apply], [data-caa-dialog-apply], [data-tlsa-dialog-apply]");
    if (!applyButton) {
      return;
    }

    const dialog = applyButton.closest("dialog[data-record-dialog]");
    if (!dialog) return;

    const formID = (dialog.dataset.recordDialogFormId || "").trim();
    if (formID === "") return;

    const context = recordFormContexts.get(formID);
    if (!context) return;

    applyRecordDialogValues(dialog, context);
  });

  document.body.addEventListener("pointerdown", (event) => {
    const contentInput = event.target.closest("input[name='content']");
    if (!contentInput) return;

    const form = contentInput.closest("form[data-record-form]");
    if (!form) return;

    const context = getContextFromForm(form);
    if (!context) return;

    const selectedType = (context.typeInput.value || "").trim().toUpperCase();
    if (!context.dialogByType[selectedType]) return;

    event.preventDefault();
    event.stopPropagation();
    openDialogByType(context, selectedType);
  });

  document.body.addEventListener("htmx:confirm", (event) => {
    const detail = event.detail || {};
    const question = (detail.question || "").trim();
    if (!question) return;

    event.preventDefault();

    if (!confirmDialog || typeof confirmDialog.showModal !== "function") {
      if (window.confirm(question) && typeof detail.issueRequest === "function") {
        detail.issueRequest(true);
      }
      return;
    }

    pendingConfirmIssueRequest = typeof detail.issueRequest === "function" ? detail.issueRequest : null;
    if (!pendingConfirmIssueRequest) return;

    if (confirmDialogTitle) {
      confirmDialogTitle.textContent = confirmDialogDefaultTitle || confirmDialogTitle.textContent;
    }
    if (confirmDialogMessage) {
      confirmDialogMessage.textContent = question;
    }

    confirmDialog.showModal();
  });

  document.body.addEventListener("htmx:beforeRequest", (event) => {
    const detail = event.detail || {};
    const trigger = detail.requestConfig ? detail.requestConfig.elt : null;
    if (!trigger || !trigger.closest) {
      preservedScrollY = null;
      return;
    }

    if (trigger.closest("[data-preserve-scroll='1']")) {
      preservedScrollY = window.scrollY;
      return;
    }

    preservedScrollY = null;
  });

  document.body.addEventListener("htmx:afterSwap", (event) => {
    bindCollapsePersistence(event.target);
    ensureRecordFormContexts(event.target);
    requestAnimationFrame(updateScrollTopButtonVisibility);

    const detail = event.detail || {};
    const target = detail.target;
    const trigger = detail.requestConfig ? detail.requestConfig.elt : null;

    if (
      preservedScrollY !== null &&
      trigger &&
      trigger.closest &&
      trigger.closest("[data-preserve-scroll='1']")
    ) {
      const y = preservedScrollY;
      preservedScrollY = null;
      requestAnimationFrame(() => {
        window.scrollTo(window.scrollX, y);
        requestAnimationFrame(() => window.scrollTo(window.scrollX, y));
      });
      return;
    }

    if (!target || target.id !== "zone-editor" || !trigger) return;
    const source = trigger.closest ? trigger.closest("[data-zone-select='1']") : null;
    if (!source) return;

    setActiveZoneSelection(source);
    requestAnimationFrame(() => {
      const currentEditor = document.getElementById("zone-editor");
      if (!currentEditor) return;
      currentEditor.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  bindCollapsePersistence(document);
  ensureRecordFormContexts(document);
})();
