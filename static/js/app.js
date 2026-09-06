(() => {
  // Convert UTC timestamps to the visitor's local time.
  document.querySelectorAll("[data-utc]").forEach((el) => {
    const parsed = new Date(el.dataset.utc);
    if (!isNaN(parsed.getTime())) {
      el.textContent = parsed.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    }
  });

  // Copy-to-clipboard helper.
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const text = btn.dataset.copy;
      try {
        await navigator.clipboard.writeText(text);
        const original = btn.innerHTML;
        btn.innerHTML = '<i class="bi bi-check-lg"></i> Copied';
        setTimeout(() => (btn.innerHTML = original), 1600);
      } catch (_) {
        const input = document.createElement("textarea");
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand("copy");
        input.remove();
      }
    });
  });

  // Auto-dismiss flash alerts.
  document.querySelectorAll(".alert[data-auto-dismiss]").forEach((el) => {
    setTimeout(() => el.classList.add("fade"), 4500);
    setTimeout(() => el.remove(), 5200);
  });

  // Confirm dangerous actions.
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (e) => {
      const message = form.dataset.confirm || "Are you sure?";
      if (!window.confirm(message)) {
        e.preventDefault();
      }
    });
  });
})();