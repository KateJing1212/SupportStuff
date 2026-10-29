/* F2 editing controls attached to the existing data-entry page. */
(function () {
  const relPlans = {
    cves: [{ type: "cve-cwe", left: "cve_id", right: "cwe_id", target: "CWE ID", direction: "left" }],
    cwes: [{ type: "cwe-capec", left: "cwe_id", right: "capec_id", target: "CAPEC ID", direction: "left" }],
    capecs: [{ type: "capec-attack", left: "capec_id", right: "attack_id", target: "ATT&CK 技术 ID", direction: "left" }],
    techniques: [
      { type: "technique-tactic", left: "attack_id", right: "tactic_id", target: "战术 ID", direction: "left" },
      { type: "technique-mitigation", left: "attack_id", right: "mitigation_id", target: "缓解措施 ID", direction: "left" }
    ],
    tactics: [{ type: "technique-tactic", left: "attack_id", right: "tactic_id", target: "ATT&CK 技术 ID", direction: "right" }],
    mitigations: [{ type: "technique-mitigation", left: "attack_id", right: "mitigation_id", target: "ATT&CK 技术 ID", direction: "right" }]
  };

  function api(path, options) {
    return fetch(path, options || {}).then(async response => {
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error?.message || `服务返回 ${response.status}`);
      return data;
    });
  }

  function editorFields(data, catalog) {
    return catalog === "cves"
      ? [
          ["title", "标题", data.title || "", "text"],
          ["description", "描述", data.description || "", "textarea"],
          ["severity", "严重性", data.severity || "", "text"],
          ["cvss_score", "CVSS 分数", data.cvss_score ?? "", "number"]
        ]
      : [["name", "名称", data.name || "", "text"], ["description", "描述", data.description || "", "textarea"]];
  }

  function editorMarkup(data, catalog) {
    const fields = editorFields(data, catalog);
    return `<section class="f2-editor"><div class="f2-section-title">编辑知识条目</div><div class="f2-edit-grid">${fields.map(([key, label, value, type]) =>
      type === "textarea"
        ? `<label>${label}<textarea data-f2-edit="${key}" rows="3">${esc(value)}</textarea></label>`
        : `<label>${label}<input data-f2-edit="${key}" type="${type}" value="${esc(value)}" ${type === "number" ? 'min="0" max="10" step="0.1"' : ""}></label>`
    ).join("")}</div><button class="btn small" id="f2SaveFields">保存字段</button><span class="f2-action-status" id="f2SaveStatus"></span></section>`;
  }

  async function renderRelations(data, catalog, id, mount) {
    const plans = relPlans[catalog] || [];
    if (!plans.length) return;
    const section = document.createElement("section");
    section.className = "f2-editor f2-relations";
    section.innerHTML = `<div class="f2-section-title">维护知识关系</div><p class="f2-relation-help">新增关系需填写来源引用。来源信息会与关系一起保存。</p>`;
    mount.appendChild(section);

    for (const plan of plans) {
      const filterKey = plan.direction === "left" ? "left_id" : "right_id";
      const query = new URLSearchParams({ [filterKey]: id, page: "1", page_size: "500" });
      const block = document.createElement("div");
      block.className = "f2-rel-block";
      block.innerHTML = `<strong>${esc(plan.type)}</strong><div class="f2-rel-list">正在读取关系…</div><form class="f2-rel-form"><label>${esc(plan.target)}<input name="target" required placeholder="例如 T1059 / CWE-79"></label><div class="f2-rel-source"><label>来源名称<input name="source_name" value="本地表单录入" required></label><label>来源版本<input name="source_version" value="manual" required></label><label>来源引用<input name="source_ref" required placeholder="资料名、URL 或记录位置"></label><label>录入人<input name="imported_by" value="本地操作" required></label></div><button class="btn small" type="submit">添加关系</button><span class="f2-action-status"></span></form>`;
      section.appendChild(block);
      const list = block.querySelector(".f2-rel-list");
      try {
        const current = await api(`/api/f2/relationships/${plan.type}?${query}`);
        const rows = current.items || [];
        list.innerHTML = rows.length ? rows.map(row => {
          const otherKey = plan.direction === "left" ? plan.right : plan.left;
          const leftId = row[plan.left], rightId = row[plan.right];
          return `<div class="f2-rel-row"><span><b>${esc(row[otherKey])}</b><small>${esc(row.source_name)} · ${esc(row.source_version)}</small></span><button type="button" class="btn small" data-remove-rel="1">移除</button></div>`;
        }).join("") : `<small class="f2-muted">暂无关联记录</small>`;
        rows.forEach((row, index) => {
          const button = list.querySelectorAll("[data-remove-rel]")[index];
          if (!button) return;
          button.onclick = async () => {
            button.disabled = true;
            try {
              await api(`/api/f2/relationships/${plan.type}`, {
                method: "DELETE", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ [plan.left]: row[plan.left], [plan.right]: row[plan.right] })
              });
              f2LoadDetail(id); f2LoadRows();
            } catch (error) { block.querySelector(".f2-action-status").textContent = error.message; button.disabled = false; }
          };
        });
      } catch (error) { list.innerHTML = `<small class="f2-muted">关系读取失败：${esc(error.message)}</small>`; }

      block.querySelector("form").onsubmit = async event => {
        event.preventDefault();
        const form = event.currentTarget, values = Object.fromEntries(new FormData(form).entries());
        const relation = { [plan.left]: plan.direction === "left" ? id : values.target,
          [plan.right]: plan.direction === "left" ? values.target : id,
          source_name: values.source_name, source_version: values.source_version,
          source_ref: values.source_ref, imported_by: values.imported_by };
        const status = block.querySelector(".f2-action-status"), button = form.querySelector("button");
        button.disabled = true; status.textContent = "正在保存并更新映射…";
        try {
          await api(`/api/f2/relationships/${plan.type}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(relation) });
          f2SetStatus("关系已保存；关联映射已重建。");
          f2LoadDetail(id); f2LoadRows();
        } catch (error) { status.textContent = error.message; button.disabled = false; }
      };
    }
  }

  document.addEventListener("f2-detail-loaded", event => {
    const data = event.detail, catalog = f2Catalog, info = f2CatalogInfo[catalog], id = data[info.id];
    const panel = document.querySelector("#f2Detail");
    panel.insertAdjacentHTML("beforeend", editorMarkup(data, catalog));
    document.querySelector("#f2SaveFields").onclick = async buttonEvent => {
      const button = buttonEvent.currentTarget, status = document.querySelector("#f2SaveStatus"), payload = {};
      document.querySelectorAll("[data-f2-edit]").forEach(input => {
        payload[input.dataset.f2Edit] = input.type === "number" ? (input.value === "" ? null : Number(input.value)) : input.value;
      });
      button.disabled = true; status.textContent = "正在保存…";
      try {
        await api(`/api/f2/${catalog}/${encodeURIComponent(id)}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
        f2SetStatus("知识条目已更新。"); f2LoadDetail(id); f2LoadRows();
      } catch (error) { status.textContent = error.message; button.disabled = false; }
    };
    renderRelations(data, catalog, id, panel);
  });

  document.addEventListener("DOMContentLoaded", () => {
    if (activeCategory === "knowledge" && f2SelectedId) f2LoadDetail(f2SelectedId);
    const choosePackage = document.querySelector("#f2ImportBtn");
    const packageFile = document.querySelector("#f2PackageFile");
    choosePackage.onclick = () => packageFile.click();
    packageFile.onchange = async () => {
      const file = packageFile.files[0];
      if (!file) return;
      const status = document.querySelector("#f2ImportStatus");
      const form = new FormData(); form.append("file", file);
      choosePackage.disabled = true; status.textContent = "正在校验并导入…";
      try {
        const result = await api("/api/f2/packages/import", { method: "POST", body: form });
        status.textContent = result.unchanged ? "数据包内容未变化" : "离线包导入完成";
        f2Summary = await f2Request("/api/f2/summary"); f2RenderSummary();
        f2SetStatus(status.textContent); f2Page = 1; f2SelectedId = ""; await f2LoadRows();
      } catch (error) { status.textContent = error.message; f2SetStatus(`导入失败：${error.message}`, true); }
      finally { choosePackage.disabled = false; packageFile.value = ""; }
    };
  });
})();
