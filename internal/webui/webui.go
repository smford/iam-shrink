package webui

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/smford/iam-shrink/internal/multicloud"
	"github.com/smford/iam-shrink/internal/render"
)

// Server serves the single-page interactive IAM policy visualizer.
type Server struct {
	listener net.Listener
	port     int
	items    []render.ActionItem
	server   *http.Server
}

// NewServer creates a new Web UI server on 127.0.0.1:<port>.
func NewServer(port int, items []render.ActionItem) (*Server, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("binding web UI on %s: %w", addr, err)
	}

	actualPort := ln.Addr().(*net.TCPAddr).Port

	s := &Server{
		listener: ln,
		port:     actualPort,
		items:    items,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/policy", s.handlePolicyAPI)
	mux.HandleFunc("/api/render", s.handleRenderAPI)

	s.server = &http.Server{
		Handler: mux,
	}

	return s, nil
}

// Port returns the listening TCP port.
func (s *Server) Port() int {
	return s.port
}

// Start begins serving in a background goroutine.
func (s *Server) Start() {
	go func() {
		_ = s.server.Serve(s.listener)
	}()
}

// Stop closes the web UI server.
func (s *Server) Stop() {
	_ = s.server.Close()
	_ = s.listener.Close()
}

func (s *Server) handleIndex(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(htmlTemplate))
}

func (s *Server) handlePolicyAPI(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.items)
}

func (s *Server) handleRenderAPI(w http.ResponseWriter, req *http.Request) {
	type renderReq struct {
		Format   string   `json:"format"`
		Selected []string `json:"selected"`
	}

	var body renderReq
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	selectedMap := make(map[string]bool)
	for _, act := range body.Selected {
		selectedMap[strings.ToLower(act)] = true
	}

	var filtered []render.ActionItem
	for _, it := range s.items {
		if len(body.Selected) == 0 || selectedMap[strings.ToLower(it.Action)] {
			filtered = append(filtered, it)
		}
	}

	var out string
	var err error

	switch body.Format {
	case "gcp":
		out, err = multicloud.RenderGCPIAMCustomRole(filtered)
	case "azure":
		out, err = multicloud.RenderAzureRBAC(filtered)
	case "k8s":
		out = multicloud.RenderK8sRBAC(filtered)
	default:
		fmtType := render.FormatType(body.Format)
		if fmtType == "" {
			fmtType = render.FormatTF
		}
		out, err = render.Render(filtered, render.RenderOptions{
			Format:         fmtType,
			GroupByService: true,
			StrictARNs:     true,
		})
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>iam-shrink — Policy Visualizer & Graph Studio</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: #0f172a; color: #f8fafc; display: flex; flex-direction: column; height: 100vh; }
    header { background: #1e293b; border-bottom: 1px solid #334155; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
    h1 { font-size: 1.25rem; font-weight: 700; color: #38bdf8; display: flex; align-items: center; gap: 0.5rem; }
    .badge { background: #0284c7; color: white; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; }
    main { display: flex; flex: 1; overflow: hidden; }
    .sidebar { width: 320px; background: #1e293b; border-right: 1px solid #334155; padding: 1.5rem; display: flex; flex-direction: column; overflow-y: auto; }
    .content { flex: 1; display: flex; flex-direction: column; padding: 1.5rem; overflow-y: auto; gap: 1.5rem; }
    .tabs { display: flex; gap: 0.5rem; background: #0f172a; padding: 0.25rem; border-radius: 8px; border: 1px solid #334155; width: fit-content; }
    .tab-btn { background: transparent; border: none; color: #94a3b8; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-weight: 500; }
    .tab-btn.active { background: #38bdf8; color: #0f172a; }
    pre { background: #090d16; border: 1px solid #334155; border-radius: 8px; padding: 1.25rem; color: #e2e8f0; font-family: ui-monospace, monospace; font-size: 0.9rem; overflow-x: auto; flex: 1; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1rem; }
    .action-item { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; font-size: 0.85rem; }
    svg { width: 100%; height: 260px; background: #090d16; border-radius: 8px; border: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <h1>🛡️ iam-shrink <span class="badge">Visualizer</span></h1>
    <span style="font-size: 0.85rem; color: #94a3b8;">Local-to-Least-Privilege Policy Studio</span>
  </header>
  <main>
    <div class="sidebar">
      <h3 style="font-size: 0.9rem; text-transform: uppercase; color: #94a3b8; margin-bottom: 1rem;">Observed Actions</h3>
      <div id="actions-list">Loading...</div>
    </div>
    <div class="content">
      <div class="card">
        <h4 style="margin-bottom: 0.75rem; color: #38bdf8;">Visual Access Flow Graph</h4>
        <svg id="graph-svg">
          <circle cx="80" cy="130" r="40" fill="#0284c7" />
          <text x="80" y="135" fill="white" font-size="12" text-anchor="middle">Principal</text>
          <line x1="120" y1="130" x2="280" y2="130" stroke="#38bdf8" stroke-width="2" stroke-dasharray="4" />
          <rect x="280" y="90" width="140" height="80" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="2" />
          <text x="350" y="125" fill="#38bdf8" font-size="14" text-anchor="middle" font-weight="bold">AWS APIs</text>
          <text x="350" y="145" fill="#94a3b8" font-size="11" text-anchor="middle">Least Privilege</text>
          <line x1="420" y1="130" x2="580" y2="130" stroke="#38bdf8" stroke-width="2" stroke-dasharray="4" />
          <rect x="580" y="90" width="160" height="80" rx="8" fill="#1e293b" stroke="#10b981" stroke-width="2" />
          <text x="660" y="125" fill="#10b981" font-size="14" text-anchor="middle" font-weight="bold">ARNs</text>
          <text x="660" y="145" fill="#94a3b8" font-size="11" text-anchor="middle">Scoped Resources</text>
        </svg>
      </div>
      <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('tf')">Terraform HCL</button>
        <button class="tab-btn" onclick="switchTab('cdk')">AWS CDK</button>
        <button class="tab-btn" onclick="switchTab('pulumi')">Pulumi</button>
        <button class="tab-btn" onclick="switchTab('cfn')">CloudFormation</button>
        <button class="tab-btn" onclick="switchTab('gcp')">Google Cloud IAM</button>
        <button class="tab-btn" onclick="switchTab('azure')">Azure RBAC</button>
        <button class="tab-btn" onclick="switchTab('json')">IAM JSON</button>
      </div>
      <pre id="output-code">Generating policy...</pre>
    </div>
  </main>
  <script>
    let currentFormat = 'tf';
    let allActions = [];

    async function init() {
      const resp = await fetch('/api/policy');
      allActions = await resp.json();
      renderSidebar();
      updatePolicy();
    }

    function renderSidebar() {
      const container = document.getElementById('actions-list');
      container.innerHTML = '';
      allActions.forEach(it => {
        const div = document.createElement('div');
        div.className = 'action-item';
        div.innerHTML = '<input type="checkbox" checked value="' + it.Action + '" onchange="updatePolicy()"> <span>' + it.Action + '</span>';
        container.appendChild(div);
      });
    }

    function switchTab(fmt) {
      currentFormat = fmt;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      updatePolicy();
    }

    async function updatePolicy() {
      const checkboxes = document.querySelectorAll('#actions-list input:checked');
      const selected = Array.from(checkboxes).map(c => c.value);
      const resp = await fetch('/api/render', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: currentFormat, selected: selected })
      });
      const code = await resp.text();
      document.getElementById('output-code').innerText = code;
    }

    window.onload = init;
  </script>
</body>
</html>`
