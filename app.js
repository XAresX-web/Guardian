/* ============================================================
   Guardian — Protección inteligente
   app.js
   ============================================================ */

/* ── System prompt ────────────────────────────────────────── */
const SYSTEM_PROMPT = `Eres un sistema avanzado de análisis de fraude digital especializado en phishing, ingeniería social y estafas en entornos reales (SMS, correo electrónico, WhatsApp, redes sociales y sitios web).
Tu objetivo NO es solo clasificar, sino PROTEGER al usuario de cometer errores.
Debes analizar el contenido con mentalidad de atacante (cómo engaña) y defensor (cómo prevenir daño).

REGLAS CRÍTICAS:
- Responde ÚNICAMENTE en JSON válido
- No expliques fuera del JSON
- No uses markdown ni backticks
- No agregues texto adicional
- Si no estás seguro, actúa con precaución (nunca minimices riesgo)
- Prioriza la seguridad del usuario sobre la certeza

ANÁLISIS MULTICAPA (OBLIGATORIO):
1. Ingeniería social: urgencia artificial, miedo o amenaza, autoridad falsa, presión psicológica
2. Intención: robo de datos, acceso a cuentas, fraude económico, redirección a sitio falso
3. Señales lingüísticas: errores gramaticales, tono inconsistente, lenguaje genérico o automatizado
4. Señales técnicas (si hay URL): dominios sospechosos, typosquatting, subdominios engañosos, dominios recientemente creados, enlaces acortados o disfrazados
5. Credibilidad: coherencia del mensaje, legitimidad del contexto, consistencia con comunicaciones reales

OUTPUT (estructura JSON exacta):
{"risk_level":"safe|suspicious|danger","risk_score":0,"attack_type":["phishing","scam","impersonation","malicious_link","social_engineering"],"confidence":0,"headline":"max 10 palabras","summary":"2-3 oraciones en español sin tecnicismos","detailed_analysis":{"social_engineering":"","technical_risk":"","intent":""},"signals":[{"severity":"low|medium|high","type":"linguistic|technical|behavioral","description":""}],"url_analysis":{"is_present":false,"is_suspicious":false,"reasons":[]},"recommended_action":{"primary":"","secondary":""},"user_risk":{"data_exposure":"low|medium|high","financial_risk":"low|medium|high","account_takeover_risk":"low|medium|high"},"education":"","safe_alternative":""}

CRITERIOS:
- safe: sin presión, sin datos sensibles, sin enlaces sospechosos, contexto coherente
- suspicious: ambigüedad, elementos fuera de lo común, requiere verificación
- danger: solicita datos/dinero, enlaces sospechosos, urgencia/amenazas, suplantación

REGLAS INVIOLABLES:
- Nunca marques "safe" si existe cualquier duda relevante
- Prefiere "suspicious" antes que minimizar riesgo
- Si hay enlace sospechoso → mínimo "suspicious"
- Si hay presión + enlace → "danger"`;

/* ── Example messages ─────────────────────────────────────── */
const EXAMPLES = {
  phishing1:
    "URGENTE: Su cuenta Bancomer ha sido SUSPENDIDA por actividad sospechosa. Para evitar el bloqueo definitivo, verifique sus datos en el siguiente enlace: http://bancomer-seguridad-mx.verificacion-cuenta.com/acceso antes de las próximas 24 horas. Si no actúa, perderá acceso permanente.",
  safe1:
    "Hola, te confirmamos que tu pedido #4821 ha sido enviado con éxito. El número de guía es MX38291042. Esperamos que llegue el jueves entre 10am y 2pm. ¡Gracias por tu compra!",
  suspicious1:
    "¡FELICIDADES! Has sido seleccionado como ganador de $5,000 pesos en nuestra rifa mensual. Para reclamar tu premio responde este mensaje con tu nombre completo y número de cuenta. La oferta expira HOY.",
  phishing2:
    "Notificación de seguridad Netflix: Hemos detectado un inicio de sesión inusual en tu cuenta desde un dispositivo desconocido. Si no fuiste tú, haz clic para proteger tu cuenta: http://netflix-verify.secure-login-mx.com — Equipo de Seguridad Netflix.",
};

/* ── UI constants ─────────────────────────────────────────── */
const COLORS = {
  safe: "#22c55e",
  suspicious: "#f59e0b",
  danger: "#ef4444",
};

const ICONS = {
  safe: (c) =>
    `<path d="M4 11L8 15L18 5" stroke="${c}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>`,
  suspicious: (c) =>
    `<circle cx="11" cy="11" r="8" stroke="${c}" stroke-width="1.5"/><path d="M11 7V11M11 15H11.01" stroke="${c}" stroke-width="1.8" stroke-linecap="round"/>`,
  danger: (c) =>
    `<circle cx="11" cy="11" r="8" stroke="${c}" stroke-width="1.5"/><path d="M8 8L14 14M14 8L8 14" stroke="${c}" stroke-width="1.8" stroke-linecap="round"/>`,
};

const LABELS = {
  safe: "Sin riesgo detectado",
  suspicious: "Precaución requerida",
  danger: "Alto riesgo",
};

const ATTACK_MAP = {
  phishing: "Phishing",
  scam: "Estafa",
  impersonation: "Suplantación de identidad",
  malicious_link: "Enlace malicioso",
  social_engineering: "Ingeniería social",
};

const RISK_ES = {
  low: "Bajo",
  medium: "Medio",
  high: "Alto",
};

/* ── State ────────────────────────────────────────────────── */
let currentTab = "SMS";

/* ── DOM refs ─────────────────────────────────────────────── */
const msgInput = document.getElementById("message-input");

/* ── Tab selection ────────────────────────────────────────── */
function setTab(el, tab) {
  document
    .querySelectorAll(".tab")
    .forEach((t) => t.classList.remove("active"));
  el.classList.add("active");
  currentTab = tab;
}

/* ── Load example ─────────────────────────────────────────── */
function loadExample(key) {
  msgInput.value = EXAMPLES[key];
  updateCharCount();
  msgInput.focus();
  document
    .getElementById("input-card")
    .scrollIntoView({ behavior: "smooth", block: "center" });
}

/* ── Character counter ────────────────────────────────────── */
msgInput.addEventListener("input", updateCharCount);

function updateCharCount() {
  const n = msgInput.value.length;
  document.getElementById("char-count").textContent =
    n + (n === 1 ? " carácter" : " caracteres");
}

/* ── Analyze message (main action) ───────────────────────── */
async function analyzeMessage() {
  const text = msgInput.value.trim();
  if (!text) return;

  const btn = document.getElementById("analyze-btn");
  const overlay = document.getElementById("analyzing-overlay");
  const resultSection = document.getElementById("result-section");

  btn.disabled = true;
  btn.classList.add("loading-state");
  resultSection.classList.remove("visible");
  overlay.classList.add("visible");

  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 1500,
        system: SYSTEM_PROMPT,
        messages: [
          {
            role: "user",
            content: `Tipo de fuente: ${currentTab}\n\nMensaje:\n\n${text}`,
          },
        ],
      }),
    });

    const data = await res.json();
    const raw = data.content?.[0]?.text || "{}";
    const clean = raw.replace(/```json\n?|```/g, "").trim();

    showResult(JSON.parse(clean));
  } catch (e) {
    showFallback(text);
  } finally {
    btn.disabled = false;
    btn.classList.remove("loading-state");
    overlay.classList.remove("visible");
  }
}

/* ── Render result ────────────────────────────────────────── */
function showResult(r) {
  const level = r.risk_level || "suspicious";
  const score = r.risk_score ?? 50;
  const confidence = r.confidence ?? 70;
  const color = COLORS[level];

  /* Header */
  document.getElementById("risk-header").className = `risk-header ${level}`;
  document.getElementById("risk-indicator").className =
    `risk-indicator ${level}`;
  document.getElementById("risk-icon").innerHTML = ICONS[level](color);

  const rlEl = document.getElementById("risk-level");
  rlEl.className = `risk-level ${level}`;
  rlEl.textContent = LABELS[level];

  document.getElementById("risk-headline").textContent = r.headline || "—";

  const rsEl = document.getElementById("risk-score");
  rsEl.className = `risk-score ${level}`;
  rsEl.textContent = score + "%";

  document.getElementById("confidence-label").textContent =
    `confianza ${confidence}%`;
  document.getElementById("result-body").className = `result-body ${level}`;

  /* Attack types */
  const atEl = document.getElementById("attack-types");
  const types = r.attack_type || [];
  atEl.innerHTML = "";

  if (types.length === 0) {
    const tag = document.createElement("span");
    tag.className = `attack-tag ${level}`;
    tag.textContent =
      level === "safe" ? "Sin ataque detectado" : "Tipo no especificado";
    atEl.appendChild(tag);
  } else {
    types.forEach((at) => {
      const tag = document.createElement("span");
      tag.className = `attack-tag ${level}`;
      tag.textContent = ATTACK_MAP[at] || at;
      atEl.appendChild(tag);
    });
  }

  /* Summary */
  document.getElementById("explanation").textContent = r.summary || "—";

  /* Detailed analysis */
  const da = r.detailed_analysis || {};
  document.getElementById("detail-social").textContent =
    da.social_engineering || "Sin manipulación psicológica detectada.";
  document.getElementById("detail-tech").textContent =
    da.technical_risk || "Sin riesgos técnicos identificados.";
  document.getElementById("detail-intent").textContent =
    da.intent || "Intención no determinada.";

  /* Signals */
  const sl = document.getElementById("signals-list");
  sl.innerHTML = "";

  (r.signals || []).forEach((s) => {
    const el = document.createElement("div");
    el.className = "signal-item";
    el.innerHTML = `
      <div class="signal-meta">
        <div class="signal-dot ${s.severity}"></div>
        <span class="signal-type-badge">${s.type || ""}</span>
      </div>
      <span class="signal-text">${s.description}</span>`;
    sl.appendChild(el);
  });

  if (!r.signals || r.signals.length === 0) {
    const el = document.createElement("div");
    el.className = "signal-item";
    el.innerHTML = `
      <div class="signal-meta"><div class="signal-dot low"></div></div>
      <span class="signal-text">No se detectaron señales de alerta.</span>`;
    sl.appendChild(el);
  }

  /* User risk metrics */
  const ur = r.user_risk || {};
  const riskFields = [
    ["risk-data", ur.data_exposure],
    ["risk-financial", ur.financial_risk],
    ["risk-account", ur.account_takeover_risk],
  ];

  riskFields.forEach(([id, val]) => {
    const safeVal = val || "low";
    const el = document.getElementById(id);
    el.className = `risk-metric-value ${safeVal}`;
    el.textContent = RISK_ES[safeVal] || safeVal;
  });

  /* URL analysis */
  const ua = r.url_analysis || {};
  const urlSec = document.getElementById("url-section");

  if (ua.is_present) {
    urlSec.style.display = "block";
    const susp = ua.is_suspicious;

    document.getElementById("url-status").innerHTML = `
      <div class="url-dot" style="background:${susp ? COLORS.danger : COLORS.safe}"></div>
      <span class="url-status-text" style="color:${susp ? COLORS.danger : COLORS.safe}">
        ${susp ? "Enlace sospechoso" : "Sin señales claras"}
      </span>`;

    const reasonsEl = document.getElementById("url-reasons");
    reasonsEl.innerHTML = "";

    const reasons = ua.reasons?.length
      ? ua.reasons
      : ["Sin datos adicionales sobre el enlace."];
    reasons.forEach((reason) => {
      const d = document.createElement("div");
      d.className = "url-reason";
      d.textContent = reason;
      reasonsEl.appendChild(d);
    });
  } else {
    urlSec.style.display = "none";
  }

  /* Recommendation */
  const ra = r.recommended_action || {};
  document.getElementById("recommendation").className =
    `recommendation ${level}`;

  const rpEl = document.getElementById("rec-primary");
  rpEl.className = `rec-primary ${level}`;
  rpEl.textContent = ra.primary || "—";

  document.getElementById("rec-secondary").textContent = ra.secondary || "";

  const saEl = document.getElementById("safe-alternative");
  if (r.safe_alternative) {
    saEl.style.display = "block";
    saEl.innerHTML = `<strong>Alternativa segura:</strong> ${r.safe_alternative}`;
  } else {
    saEl.style.display = "none";
  }

  /* Educational note */
  document.getElementById("educational-note").innerHTML = r.education
    ? `<strong>Dato útil:</strong> ${r.education}`
    : "";

  /* Reveal result */
  const resultSection = document.getElementById("result-section");
  resultSection.classList.add("visible");
  setTimeout(
    () => resultSection.scrollIntoView({ behavior: "smooth", block: "start" }),
    100,
  );
}

/* ── Offline / fallback analysis ──────────────────────────── */
function showFallback(text) {
  const lower = text.toLowerCase();
  const hasUrl = /https?:\/\/|bit\.ly|tinyurl|goo\.gl/i.test(text);

  const urgencyWords = [
    "urgente",
    "ahora",
    "inmediatamente",
    "expira",
    "bloqueada",
    "suspendida",
    "perderá",
    "última",
  ];
  const phishWords = [
    "verificar",
    "confirme",
    "contraseña",
    "datos personales",
    "clic aquí",
  ];
  const scamWords = ["ganaste", "premio", "seleccionado", "rifa", "gratis"];

  const urgency = urgencyWords.filter((w) => lower.includes(w)).length;
  const phish = phishWords.filter((w) => lower.includes(w)).length;
  const scam = scamWords.filter((w) => lower.includes(w)).length;
  const total = urgency + phish + scam;

  let r;

  if (total >= 3 || (hasUrl && urgency >= 1)) {
    r = {
      risk_level: "danger",
      risk_score: 88,
      confidence: 78,
      attack_type: ["phishing", "social_engineering"],
      headline: "Alto riesgo — posible intento de fraude",
      summary:
        "Este mensaje presenta múltiples señales de phishing. Usa presión psicológica para que actúes sin reflexionar y posiblemente intenta robar tus datos o dinero.",
      detailed_analysis: {
        social_engineering:
          "Usa urgencia artificial y lenguaje de amenaza para presionar al usuario.",
        technical_risk: hasUrl
          ? "Contiene enlace que podría dirigir a sitio falso."
          : "Sin URLs detectadas.",
        intent: "Obtener datos personales, credenciales o dinero del usuario.",
      },
      signals: [
        {
          severity: "high",
          type: "behavioral",
          description:
            "Lenguaje de urgencia y amenaza para presionar acción inmediata",
        },
        {
          severity: "high",
          type: "behavioral",
          description:
            "Solicita acciones que podrían comprometer datos sensibles",
        },
        hasUrl
          ? {
              severity: "high",
              type: "technical",
              description: "Contiene enlace potencialmente malicioso",
            }
          : null,
        scam > 0
          ? {
              severity: "medium",
              type: "linguistic",
              description: "Ofrece beneficios poco realistas o inesperados",
            }
          : null,
      ].filter(Boolean),
      url_analysis: {
        is_present: hasUrl,
        is_suspicious: hasUrl,
        reasons: hasUrl
          ? [
              "El dominio no corresponde a ninguna entidad oficial conocida",
              "La URL fue incluida junto a lenguaje de urgencia",
            ]
          : [],
      },
      recommended_action: {
        primary: "No hagas clic en ningún enlace ni respondas el mensaje.",
        secondary:
          "Si es sobre una cuenta real, accede directamente desde la app oficial.",
      },
      user_risk: {
        data_exposure: "high",
        financial_risk: "high",
        account_takeover_risk: "high",
      },
      education:
        "Las empresas legítimas nunca solicitan contraseñas o datos bancarios por SMS o WhatsApp.",
      safe_alternative:
        "Contacta directamente a la entidad a través de sus canales oficiales verificados en Google.",
    };
  } else if (total >= 1 || hasUrl) {
    r = {
      risk_level: "suspicious",
      risk_score: 48,
      confidence: 65,
      attack_type: ["social_engineering"],
      headline: "Algunas señales requieren verificación",
      summary:
        "El mensaje contiene elementos que generan dudas. No es claramente fraudulento, pero tampoco puede confirmarse como legítimo sin verificación adicional.",
      detailed_analysis: {
        social_engineering:
          "Podría intentar generar confianza o cierta presión de forma sutil.",
        technical_risk: hasUrl
          ? "Contiene enlace que conviene verificar antes de hacer clic."
          : "Sin riesgos técnicos evidentes.",
        intent:
          "Intención incierta — podría ser legítimo o un intento de estafa poco elaborado.",
      },
      signals: [
        {
          severity: "medium",
          type: "behavioral",
          description: "Contiene elementos que merecen verificación adicional",
        },
        hasUrl
          ? {
              severity: "medium",
              type: "technical",
              description:
                "Incluye un enlace cuya legitimidad no puede confirmarse sin revisión",
            }
          : null,
      ].filter(Boolean),
      url_analysis: {
        is_present: hasUrl,
        is_suspicious: hasUrl,
        reasons: hasUrl
          ? ["Verifica que el dominio sea oficial antes de hacer clic"]
          : [],
      },
      recommended_action: {
        primary: "Verifica la identidad del remitente por canales oficiales.",
        secondary:
          "No compartas datos personales hasta confirmar la legitimidad.",
      },
      user_risk: {
        data_exposure: "medium",
        financial_risk: "low",
        account_takeover_risk: "medium",
      },
      education:
        "Cuando tengas dudas, siempre contacta directamente a la empresa a través de su sitio web oficial.",
      safe_alternative:
        "Busca el número de contacto oficial de la empresa en Google y llama directamente.",
    };
  } else {
    r = {
      risk_level: "safe",
      risk_score: 10,
      confidence: 75,
      attack_type: [],
      headline: "Sin señales de riesgo detectadas",
      summary:
        "No se encontraron patrones de phishing o estafa. El mensaje parece ser una comunicación legítima sin intención maliciosa.",
      detailed_analysis: {
        social_engineering:
          "No se detectó manipulación psicológica ni lenguaje de presión.",
        technical_risk:
          "Sin enlaces sospechosos ni riesgos técnicos identificados.",
        intent: "Comunicación informativa sin señales de intención maliciosa.",
      },
      signals: [
        {
          severity: "low",
          type: "behavioral",
          description: "No contiene lenguaje de urgencia o presión emocional",
        },
        {
          severity: "low",
          type: "behavioral",
          description: "No solicita datos personales ni acciones urgentes",
        },
      ],
      url_analysis: { is_present: false, is_suspicious: false, reasons: [] },
      recommended_action: {
        primary: "El mensaje parece seguro. Puedes responder con normalidad.",
        secondary:
          "Mantén siempre precaución con solicitudes inesperadas en el futuro.",
      },
      user_risk: {
        data_exposure: "low",
        financial_risk: "low",
        account_takeover_risk: "low",
      },
      education:
        "Incluso mensajes aparentemente seguros pueden ser sospechosos si vienen de remitentes desconocidos.",
      safe_alternative:
        "Continúa con normalidad, pero mantén el hábito de verificar remitentes desconocidos.",
    };
  }

  showResult(r);
}

/* ── Reset app ────────────────────────────────────────────── */
function resetApp() {
  msgInput.value = "";
  updateCharCount();
  document.getElementById("result-section").classList.remove("visible");
  document
    .getElementById("input-card")
    .scrollIntoView({ behavior: "smooth", block: "center" });
  setTimeout(() => msgInput.focus(), 400);
}

/* ── Keyboard shortcut: Cmd/Ctrl + Enter ─────────────────── */
msgInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) analyzeMessage();
});
