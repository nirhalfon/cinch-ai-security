/* ── Cinch — SPA Engine ── */
const DATA_URL = 'data/full.json';
let D = null; // full data cache

// HTML-escape for any data-field text interpolated directly into markup.
// Content passed through md() is already escaped; this is for titles, ids,
// threat/control text, tags, and other fields rendered raw. Prevents stored
// XSS via a malicious checklist/mapping/template contribution.
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

async function loadData() {
  if (D) return D;
  const r = await fetch(DATA_URL);
  D = await r.json();
  return D;
}

// ── Markdown-lite renderer ──
function md(text) {
  if (!text) return '';
  return text
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/^### (.+)$/gm,'<h4>$1</h4>')
    .replace(/^## (.+)$/gm,'<h3>$1</h3>')
    .replace(/^# (.+)$/gm,'<h2>$1</h2>')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,'<em>$1</em>')
    .replace(/`([^`]+)`/g,'<code>$1</code>')
    .replace(/^\- \[([ x])\] (.+)$/gm,(m,c,t)=>`<div class="ci"><input type="checkbox" ${c==='x'?'checked':''} disabled>${t}</div>`)
    .replace(/^\- (.+)$/gm,'<li>$1</li>')
    .replace(/^> (.+)$/gm,'<blockquote>$1</blockquote>')
    .replace(/^\|(.+)\|$/gm,(m)=>{
      const cells=m.split('|').filter(c=>c.trim());
      if(cells.every(c=>/^[\-\s:]+$/.test(c.trim())))return'';
      return'<tr>'+cells.map(c=>`<td>${c.trim()}</td>`).join('')+'</tr>';
    })
    .replace(/\n{2,}/g,'<br><br>')
    .replace(/\n/g,' ');
}

function sevClass(s) {
  s=(s||'').toLowerCase();
  if(s==='critical')return'tag-critical';
  if(s==='high')return'tag-high';
  if(s==='medium')return'tag-medium';
  return'tag-low';
}

function renderItem(item) {
  // Two checklist schemas exist:
  //  - Schema A (agent-containment): threat / control / verification / sources
  //  - Schema B (the other four): title / description / validation / references
  // Render whichever fields are present so every checklist is legible.
  const isA = item.threat != null;
  const heading = isA ? item.threat : (item.title || '');
  const body = isA
    ? `<div class="ci-control">${esc(item.control)}</div>
       <div class="ci-verification"><strong>✓ Verify:</strong> ${esc(item.verification)}</div>`
    : `<div class="ci-control">${esc(item.description || '')}</div>
       ${item.validation ? `<div class="ci-verification"><strong>✓ Verify:</strong> ${esc(item.validation.type || '')}${item.validation.evidence_required ? ' — ' + esc(item.validation.evidence_required) : ''}</div>` : ''}`;
  const refs = (item.sources && item.sources.length)
    ? `<div class="ci-sources">Sources: ${item.sources.map(s=>`<code>${esc(s)}</code>`).join(', ')}</div>`
    : (item.references && item.references.length)
      ? `<div class="ci-sources">References: ${item.references.map(s=>`<code>${esc(s)}</code>`).join(', ')}</div>`
      : '';
  return `<div class="checklist-item" id="${esc(item.id)}">
    <div class="ci-header">
      <span class="ci-id">${esc(item.id)}</span>
      <span class="ci-threat">${esc(heading)}</span>
      <span class="tag ${sevClass(item.severity)}">${esc(item.severity)}</span>
    </div>
    ${body}
    <div class="ci-tags">
      ${item.custody_pillar?`<span class="tag tag-pillar">${esc(item.custody_pillar)}</span>`:''}
      ${item.lasm_layer?`<span class="tag tag-layer">${esc(item.lasm_layer)}</span>`:''}
      ${item.weight?`<span class="tag tag-framework">Weight: ${esc(item.weight)}</span>`:''}
      ${item.category?`<span class="tag tag-framework">${esc(item.category.replace(/_/g,' '))}</span>`:''}
    </div>
    ${refs}
  </div>`;
}

function renderChecklistPage(key, cl) {
  const items = cl.items||[];
  const meta = cl.meta||{};
  const categories = [...new Set(items.map(i=>i.category).filter(Boolean))];
  return `<div class="detail-header">
    <h1>${esc(meta.name||key)}</h1>
    <p class="detail-desc">${esc(meta.description||'')}</p>
    <div class="ci-tags mt-2">
      ${(meta.frameworks||[]).map(f=>`<span class="tag tag-framework">${esc(f)}</span>`).join('')}
    </div>
  </div>
  <div class="stats">
    <div class="stat"><div class="stat-num">${items.length}</div><div class="stat-label">Controls</div></div>
    <div class="stat"><div class="stat-num">${items.filter(i=>i.severity==='critical').length}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-num">${items.filter(i=>i.severity==='high').length}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-num">${categories.length}</div><div class="stat-label">Categories</div></div>
  </div>
  <div class="filter-bar" id="severity-filter">
    <button class="filter-btn active" data-sev="all">All</button>
    <button class="filter-btn" data-sev="critical">Critical</button>
    <button class="filter-btn" data-sev="high">High</button>
    <button class="filter-btn" data-sev="medium">Medium</button>
    <button class="filter-btn" data-sev="low">Low</button>
  </div>
  <div id="items-container">${items.map(i=>renderItem(i)).join('')}</div>`;
}

function renderMappingPage(key, mp) {
  const entries = mp.entries||[];
  const meta = mp.meta||{};
  const fw = entries.length>0 ? entries[0].framework : key;
  return `<div class="detail-header">
    <h1>${esc(meta.name||fw+' Crosswalk')}</h1>
    <p class="detail-desc">${esc(meta.description||'')}</p>
  </div>
  <table>
    <thead><tr><th>Control ID</th><th>Framework Control</th><th>Checklist Items</th><th>Description</th></tr></thead>
    <tbody>${entries.map(e=>`<tr>
      <td><code>${esc(e.control_id)}</code></td>
      <td>${esc(e.framework_control_name)}</td>
      <td>${(e.checklist_ids||[]).map(id=>`<code>${esc(id)}</code>`).join(' ')}</td>
      <td class="text-sm">${esc(e.description)}</td>
    </tr>`).join('')}</tbody>
  </table>`;
}

function renderMarkdownPage(title, content) {
  return `<div class="detail-header"><h1>${esc(title)}</h1></div>${md(content)}`;
}

// ── Page renderers ──
const PAGES = {
  home: () => `
    <div class="hero">
      <div class="hero-badge">v1.0.0 · 106 Controls · 5 Frameworks · Open Source</div>
      <h1>Cinch</h1>
      <p>MCP server + cross-harness skills for building and operating AI agents safely. Checklists, protocols, and mappings grounded in NIST AI RMF, CISA, OWASP, CUSTODY, and LASM.</p>
      <div class="hero-actions">
        <a href="pages/quickstart.html" class="btn btn-primary">⚡ Quick Start</a>
        <a href="pages/checklists.html" class="btn btn-secondary">📋 Checklists</a>
        <a href="pages/threat-model.html" class="btn btn-secondary">🛡️ Threat Model</a>
      </div>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-num">106</div><div class="stat-label">Controls</div></div>
      <div class="stat"><div class="stat-num">5</div><div class="stat-label">Checklists</div></div>
      <div class="stat"><div class="stat-num">5</div><div class="stat-label">Framework Maps</div></div>
      <div class="stat"><div class="stat-num">6</div><div class="stat-label">MCP Tools</div></div>
    </div>
    <h2>Philosophy</h2>
    <blockquote><strong>The model proposes; the architecture authorizes and enforces.</strong> Prompts are not a security boundary. An AI agent can be manipulated, compromised, or wrong. Its environment must prevent a bad decision from becoming an unrestricted system action.</blockquote>
    <h2>What it's meant for</h2>
    <p>AI agents can read data, invoke tools, execute code, call APIs, and initiate business processes. When they go wrong — through prompt injection, excessive autonomy, credential theft, or model error — the blast radius is only as large as the environment allows. Cinch gives you the enforceable controls, protocols, and cross-framework mappings to keep that blast radius small: prevent a bad model decision from becoming an unrestricted system action.</p>
    <h2>Who it's for</h2>
    <div class="grid grid-2">
      <div class="card"><div class="card-icon">🤖</div><h3>Agent builders</h3><p>Ship autonomous and semi-autonomous agents with machine-readable authorization artifacts, supervision gates, and rollback before live access.</p></div>
      <div class="card"><div class="card-icon">🛠️</div><h3>Platform & SRE teams</h3><p>Harden the harness where AI writes, reviews, and deploys code — least privilege, tool boundaries, runtime controls, and observability.</p></div>
      <div class="card"><div class="card-icon">🛡️</div><h3>Security & red-team engineers</h3><p>Run structured adversarial testing and incident response against the LASM 7×4 threat model and CUSTODY pillars.</p></div>
      <div class="card"><div class="card-icon">📋</div><h3>AI governance leads</h3><p>Map controls to NIST AI RMF, OWASP, MITRE ATLAS, CUSTODY, and LASM for auditable, cross-framework assurance.</p></div>
    </div>
    <h2>How it works</h2>
    <pre><code>YAML checklists ──┐   ┌── cross-harness skills (Claude / Hermes / OpenClaw / NanoClaw)
  (106 controls)  │   │
  protocols ──────┼─▶ MCP server (6 tools) ◀── agent queries at runtime
  mappings ───────┘   └── frameworks: NIST AI RMF · OWASP · ATLAS · CUSTODY · LASM</code></pre>
    <p class="text-muted">The agent never trusts a prompt to enforce a boundary. It asks Cinch for the control, the verification step, and the framework mapping — and the harness enforces the answer.</p>
    <h2>What's Inside</h2>
    <div class="grid grid-3">
      <div class="card"><div class="card-icon">📋</div><h3>Checklists</h3><p>106 enforceable controls across 5 checklists, each mapped to a threat and a verification step.</p><div class="card-meta"><span class="tag tag-framework">NIST</span><span class="tag tag-framework">OWASP</span><span class="tag tag-framework">CUSTODY</span></div></div>
      <div class="card"><div class="card-icon">📡</div><h3>MCP Server</h3><p>6 tools any MCP-compatible agent can query for controls, protocols, and mappings at runtime.</p><div class="card-meta"><span class="tag tag-framework">Claude</span><span class="tag tag-framework">Hermes</span><span class="tag tag-framework">OpenClaw</span></div></div>
      <div class="card"><div class="card-icon">🧠</div><h3>Skills</h3><p>Drop-in skill definitions for Hermes, Claude, OpenClaw, and NanoClaw.</p><div class="card-meta"><span class="tag tag-pillar">3 Skills</span></div></div>
      <div class="card"><div class="card-icon">📐</div><h3>Protocols</h3><p>Step-by-step deployment, incident response, red team, and harness setup procedures.</p><div class="card-meta"><span class="tag tag-pillar">4 Protocols</span></div></div>
      <div class="card"><div class="card-icon">🔗</div><h3>Mappings</h3><p>Cross-reference controls to NIST AI RMF, OWASP, MITRE ATLAS, CUSTODY, and LASM.</p><div class="card-meta"><span class="tag tag-layer">5 Frameworks</span></div></div>
      <div class="card"><div class="card-icon">🎯</div><h3>Threat Model</h3><p>LASM 7×4 matrix and CUSTODY 7 pillars for defense-in-depth agent security.</p><div class="card-meta"><span class="tag tag-critical">L1-L7</span></div></div>
    </div>`,

  checklists: async () => {
    const d = await loadData();
    let html = `<h1>Security Checklists</h1><p class="text-muted mb-4">106 enforceable controls across 5 checklists, each mapped to a threat and verification step.</p>
    <div class="tabs" id="cl-tabs">${Object.keys(d.checklists).map((k,i)=>
      `<div class="tab ${i===0?'active':''}" data-cl="${esc(k)}">${esc(d.checklists[k].meta.name||k.replace(/-/g,' ').replace(/\b\w/g,c=>c.toUpperCase()))}</div>`
    ).join('')}</div><div id="cl-content"></div>`;
    return html;
  },

  checklist_detail: async (key) => {
    const d = await loadData();
    return renderChecklistPage(key, d.checklists[key]);
  },

  protocols: async () => {
    const d = await loadData();
    return `<h1>Protocols</h1><p class="text-muted mb-4">Step-by-step security protocols for deployment, incident response, red teaming, and harness setup.</p>
    <div class="grid grid-2">${Object.entries(d.protocols).map(([k,v])=>
      `<a href="pages/protocol-detail.html?key=${encodeURIComponent(k)}" class="card"><h3>${esc(v.title)}</h3><p class="text-sm text-muted mt-2">Step-by-step security protocol</p></a>`
    ).join('')}</div>`;
  },

  protocol_detail: async (key) => {
    const d = await loadData();
    const p = d.protocols[key];
    return renderMarkdownPage(p.title, p.content);
  },

  mappings: async () => {
    const d = await loadData();
    return `<h1>Framework Mappings</h1><p class="text-muted mb-4">Cross-reference controls to NIST, OWASP, MITRE ATLAS, CUSTODY, and LASM.</p>
    <div class="grid grid-2">${Object.entries(d.mappings).map(([k,v])=>
      `<a href="pages/mapping-detail.html?key=${encodeURIComponent(k)}" class="card"><h3>${esc(v.meta.name||k.replace(/-/g,' ').replace(/\b\w/g,c=>c.toUpperCase()))}</h3><p class="text-sm text-muted mt-2">${(v.entries||[]).length} mappings</p></a>`
    ).join('')}</div>`;
  },

  mapping_detail: async (key) => {
    const d = await loadData();
    return renderMappingPage(key, d.mappings[key]);
  },

  skills: async () => {
    const d = await loadData();
    return `<h1>Hermes Skills</h1><p class="text-muted mb-4">Drop-in skill definitions for Hermes Agent. Copy to <code>~/.hermes/skills/</code>.</p>
    <div class="grid grid-3">${Object.entries(d.skills).map(([k,v])=>
      `<a href="pages/skill-detail.html?key=${encodeURIComponent(k)}" class="card"><h3>${esc((v.frontmatter||{}).name||k.replace(/-/g,' ').replace(/\b\w/g,c=>c.toUpperCase()))}</h3><p class="text-sm text-muted mt-2">${esc(((v.frontmatter||{}).description||'').substring(0,120))}...</p></a>`
    ).join('')}</div>`;
  },

  skill_detail: async (key) => {
    const d = await loadData();
    const s = d.skills[key];
    const fm = s.frontmatter||{};
    let html = `<div class="detail-header"><h1>${esc(fm.name||key)}</h1><p class="detail-desc">${esc(fm.description||'')}</p>`;
    if(fm.triggers) html+=`<div class="ci-tags mt-2">${fm.triggers.map(t=>`<span class="tag tag-framework">${esc(t)}</span>`).join('')}</div>`;
    if(fm.tools) html+=`<div class="ci-tags mt-2">${fm.tools.map(t=>`<code>${esc(t)}</code>`).join(' ')}</div>`;
    html+=`</div>${md(s.content)}`;
    return html;
  },

  threat_model: async () => {
    const d = await loadData();
    return renderMarkdownPage('Threat Model — LASM & CUSTODY', d.docs['threat-model']?.content||'');
  },

  quickstart: () => `
    <h1>⚡ Quick Start</h1>
    <h2>Install the MCP Server</h2>
    <pre><code>pip install cinch
cinch serve</code></pre>
    <h2>Add to MCP Config</h2>
    <pre><code>{
  "mcpServers": {
    "cinch": {
      "command": "cinch",
      "args": ["serve"]
    }
  }
}</code></pre>
    <h2>Use as a Hermes Skill</h2>
    <pre><code>cp -r skills/ai-harness-review ~/.hermes/skills/
cp -r skills/agent-audit ~/.hermes/skills/
cp -r skills/ai-red-team ~/.hermes/skills/</code></pre>
    <h2>Use with Claude Code</h2>
    <pre><code>cp cross-harness/claude/CLAUDE.md /your/project/CLAUDE.md</code></pre>
    <h2>Query from Any MCP Client</h2>
    <pre><code># List all checklists
checklist_list

# Run agent containment checklist
checklist_run("agent-containment")

# Search for controls that mitigate prompt injection
threat_search("prompt injection")

# Look up NIST AI RMF mappings
mapping_lookup("nist-rmf")</code></pre>
    <h2>Run in CI</h2>
    <pre><code># Validate all YAML checklists
python3 -c "import yaml, glob; [yaml.safe_load(open(f)) for f in glob.glob('checklists/*.yaml')]"

# Install harness scorecard
pip install ai-harness-scorecard
ai-harness-scorecard assess .</code></pre>`,

  mcp_server: () => `
    <h1>📡 MCP Server</h1>
    <p class="text-muted mb-4">Cinch provides an MCP server with 6 tools that any MCP-compatible agent can query at runtime.</p>
    <h2>Available Tools</h2>
    <table>
      <thead><tr><th>Tool</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td><code>checklist_list</code></td><td>List all available checklists with item counts and frameworks</td></tr>
        <tr><td><code>checklist_run</code></td><td>Run a named checklist and return all items with threat, control, severity, and verification</td></tr>
        <tr><td><code>checklist_get</code></td><td>Get a specific checklist item by ID</td></tr>
        <tr><td><code>protocol_get</code></td><td>Get a step-by-step security protocol by name</td></tr>
        <tr><td><code>mapping_lookup</code></td><td>Look up controls mapped to a framework (NIST, OWASP, CUSTODY, LASM, ATLAS)</td></tr>
        <tr><td><code>threat_search</code></td><td>Search all checklists for controls that mitigate a given threat</td></tr>
      </tbody>
    </table>
    <h2>Installation</h2>
    <pre><code>pip install cinch
cinch serve</code></pre>
    <h2>Configuration</h2>
    <pre><code>{
  "mcpServers": {
    "cinch": {
      "command": "cinch",
      "args": ["serve"]
    }
  }
}</code></pre>`,

  templates: async () => {
    const d = await loadData();
    return `<h1>Templates</h1><p class="text-muted mb-4">Policy, ADR, and risk assessment templates you can copy and customize.</p>
    <div class="grid grid-3">${Object.entries(d.templates).map(([k,v])=>
      `<a href="pages/template-detail.html?key=${encodeURIComponent(k)}" class="card"><h3>${esc(v.title)}</h3><p class="text-sm text-muted mt-2">Customizable template</p></a>`
    ).join('')}</div>`;
  },

  template_detail: async (key) => {
    const d = await loadData();
    const t = d.templates[key];
    return renderMarkdownPage(t.title, t.content);
  },
};

// ── Router ──
async function route() {
  const params = new URLSearchParams(window.location.search);
  const page = params.get('page') || 'home';
  const key = params.get('key') || '';

  const renderer = PAGES[page];
  if (!renderer) { document.getElementById('app').innerHTML = '<h1>404</h1>'; return; }

  try {
    const html = await renderer(key);
    document.getElementById('app').innerHTML = html;
    // Wire up severity filters
    document.querySelectorAll('#severity-filter .filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('#severity-filter .filter-btn').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');
        const sev = btn.dataset.sev;
        document.querySelectorAll('.checklist-item').forEach(item => {
          item.style.display = (sev==='all' || item.querySelector('.tag-critical,.tag-high,.tag-medium,.tag-low')?.textContent.trim().toLowerCase()===sev) ? '' : 'none';
        });
      });
    });
    // Wire up checklist tabs
    const clTabs = document.getElementById('cl-tabs');
    if (clTabs) {
      const d = await loadData();
      const firstKey = Object.keys(d.checklists)[0];
      const content = document.getElementById('cl-content');
      content.innerHTML = renderChecklistPage(firstKey, d.checklists[firstKey]);
      clTabs.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', async () => {
          clTabs.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
          tab.classList.add('active');
          const dd = await loadData();
          content.innerHTML = renderChecklistPage(tab.dataset.cl, dd.checklists[tab.dataset.cl]);
        });
      });
    }
  } catch(e) {
    document.getElementById('app').innerHTML = `<h1>Error</h1><p>${e.message}</p><pre>${e.stack}</pre>`;
  }
}

// ── Mobile menu ──
document.getElementById('menu-toggle')?.addEventListener('click', () => {
  document.getElementById('nav-links').classList.toggle('open');
});

// ── Run ──
route();