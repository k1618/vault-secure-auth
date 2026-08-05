/**
 * Da retroalimentación en vivo mientras el usuario escribe su contraseña:
 * - Actualiza el medidor de segmentos y el checklist de reglas al instante
 *   (cálculo local, sin llamada al servidor).
 * - Después de una pequeña pausa de inactividad (debounce), consulta
 *   /api/check-password para saber si la contraseña ya apareció en una
 *   filtración conocida (esa parte sí necesita al servidor, porque solo
 *   el backend habla con la API de Have I Been Pwned).
 */
(function () {
  const input = document.getElementById("password");
  if (!input) return;

  const gauge = document.getElementById("strength-gauge");
  const segments = document.querySelectorAll("#gauge-segments .seg");
  const checklistItems = document.querySelectorAll("#checklist li");
  const breachBadge = document.getElementById("breach-badge");

  let debounceTimer = null;

  function localChecks(password) {
    return {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      digit: /\d/.test(password),
      special: /[^A-Za-z0-9]/.test(password),
    };
  }

  function renderGauge(score) {
    segments.forEach((seg, i) => {
      seg.className = "seg";
      if (i < score) {
        seg.classList.add(
          score <= 2 ? "filled-weak" : score <= 4 ? "filled-mid" : "filled-strong"
        );
      }
    });
  }

  function renderChecklist(checks) {
    checklistItems.forEach((li) => {
      const key = li.dataset.check;
      const ok = checks[key];
      li.classList.toggle("ok", ok);
      li.querySelector(".mark").textContent = ok ? "✓" : "–";
    });
  }

  function renderBreachBadge(state, count) {
    breachBadge.className = "breach-badge";
    if (state === "checking") {
      breachBadge.classList.add("unknown");
      breachBadge.textContent = "Verificando contra filtraciones conocidas…";
    } else if (state === "unavailable") {
      breachBadge.classList.add("unknown");
      breachBadge.textContent = "No se pudo consultar el servicio de filtraciones ahora mismo.";
    } else if (count > 0) {
      breachBadge.classList.add("danger");
      breachBadge.textContent = `Esta contraseña apareció ${count.toLocaleString("es-MX")} veces en filtraciones conocidas. Elige otra.`;
    } else {
      breachBadge.classList.add("safe");
      breachBadge.textContent = "No aparece en filtraciones conocidas.";
    }
  }

  async function checkBreach(password) {
    renderBreachBadge("checking");
    try {
      const res = await fetch("/api/check-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      const data = await res.json();
      if (!data.breach_check_available) {
        renderBreachBadge("unavailable");
      } else {
        renderBreachBadge("result", data.breach_count);
      }
    } catch (err) {
      renderBreachBadge("unavailable");
    }
  }

  input.addEventListener("input", () => {
    const password = input.value;

    if (!password) {
      gauge.hidden = true;
      return;
    }
    gauge.hidden = false;

    const checks = localChecks(password);
    const score = Object.values(checks).filter(Boolean).length;
    renderGauge(score);
    renderChecklist(checks);

    clearTimeout(debounceTimer);
    if (checks.length) {
      debounceTimer = setTimeout(() => checkBreach(password), 500);
    } else {
      renderBreachBadge("unknown");
      breachBadge.textContent = "Escribe al menos 8 caracteres para verificar filtraciones.";
    }
  });
})();
