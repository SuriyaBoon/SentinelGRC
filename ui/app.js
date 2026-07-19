/* Safe UI shell. Production deployment must inject authenticated API access through the host application. */
(() => {
  const metrics = document.querySelectorAll("[data-metric]");
  if (!metrics.length) return;
  const apiBase = window.SENTINEL_API_BASE || "";
  if (!apiBase) return;
  fetch(apiBase + "/v1/governance/report", {headers: {"Accept": "application/json"}})
    .then(response => response.ok ? response.json() : Promise.reject(response.status))
    .then(report => metrics.forEach(node => {
      const value = (report.kpi && report.kpi[node.dataset.metric]) ?? report[node.dataset.metric];
      node.textContent = value === undefined ? "—" : String(value);
    }))
    .catch(() => metrics.forEach(node => { node.textContent = "—"; }));
})();