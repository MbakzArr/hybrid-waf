#!/usr/bin/env python3
"""
Module 6b: Monitoring Dashboard and Log Explorer (UC04 + UC07)
Hybrid WAF - IT28X87 Honours Project
Mbadaliga, AB (219044112)

Run from project root:
    python3 src/dashboard.py

Then open: http://localhost:8081

Two tabs:
  Overview    (UC07) - live metric cards and block analysis charts
  Log Explorer(UC04) - searchable, filterable table of all requests
"""
import csv
import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

_here = os.path.dirname(os.path.abspath(__file__))
_root = _here if os.path.exists(os.path.join(_here, 'logs')) \
        else os.path.dirname(_here)

DASHBOARD_PORT = 8081
LOG_FILE = os.path.join(_root, 'logs', 'detection_log.csv')


def read_rows(log_path: str) -> list:
    if not os.path.exists(log_path):
        return []
    try:
        with open(log_path, 'r', newline='') as f:
            return list(csv.DictReader(f))
    except Exception:
        return []


def compute_stats(rows: list) -> dict:
    stats = {
        "total": len(rows),
        "blocked": 0, "allowed": 0,
        "block_rate": "0.0%",
        "by_category": {"SQLi": 0, "XSS": 0, "PATH": 0},
        "by_trigger": {"Case A": 0, "Case B": 0, "Both agree": 0},
        "mode": "hybrid",
        "last_updated": datetime.now().strftime("%H:%M:%S"),
        "perf": {
            "count": 0,
            "avg_total_ms": 0.0, "min_total_ms": 0.0, "max_total_ms": 0.0,
            "avg_extract_ms": 0.0, "avg_rule_ms": 0.0,
            "avg_ml_ms": 0.0, "avg_decide_ms": 0.0,
        },
    }
    totals, extracts, rules_t, mls, decides = [], [], [], [], []
    for row in rows:
        action = row.get("action", "ALLOW")
        if action == "BLOCK":
            stats["blocked"] += 1
            cat = row.get("rule_category", "")
            if cat in stats["by_category"]:
                stats["by_category"][cat] += 1
            reason = row.get("reason", "")
            if "Case A" in reason:
                stats["by_trigger"]["Case A"] += 1
            elif "Case B" in reason:
                stats["by_trigger"]["Case B"] += 1
            elif "Both agree" in reason:
                stats["by_trigger"]["Both agree"] += 1
        else:
            stats["allowed"] += 1
        if row.get("mode"):
            stats["mode"] = row["mode"]

        # Timing columns are optional. Older log rows, e.g. from the
        # sample log generator, may not have them, skip quietly rather
        # than crash on a missing or blank field.
        try:
            if row.get("t_total_ms"):
                totals.append(float(row["t_total_ms"]))
                extracts.append(float(row["t_extract_ms"]))
                rules_t.append(float(row["t_rule_ms"]))
                mls.append(float(row["t_ml_ms"]))
                decides.append(float(row["t_decide_ms"]))
        except (ValueError, KeyError):
            pass

    if stats["total"] > 0:
        stats["block_rate"] = \
            f"{100*stats['blocked']/stats['total']:.1f}%"

    if totals:
        stats["perf"] = {
            "count": len(totals),
            "avg_total_ms": round(sum(totals)/len(totals), 3),
            "min_total_ms": round(min(totals), 3),
            "max_total_ms": round(max(totals), 3),
            "avg_extract_ms": round(sum(extracts)/len(extracts), 3),
            "avg_rule_ms": round(sum(rules_t)/len(rules_t), 3),
            "avg_ml_ms": round(sum(mls)/len(mls), 3),
            "avg_decide_ms": round(sum(decides)/len(decides), 3),
        }
    return stats


PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>Hybrid WAF Console</title>
<style>
:root{--bg:#0d1420;--panel:#16202e;--p2:#1c2836;--border:#263445;
--text:#dfe6ee;--muted:#7d92a8;--blue:#3d8bcd;--green:#3fb968;
--red:#e05555;--amber:#e0a838;--purple:#b45ec4;}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',Arial,sans-serif;background:var(--bg);
color:var(--text);padding:20px;font-size:14px;}
.wrap{max-width:1200px;margin:0 auto;}
.header{display:flex;justify-content:space-between;align-items:center;
background:linear-gradient(135deg,#002a52,#013b6e);padding:16px 24px;
border-radius:10px;margin-bottom:16px;}
.header h1{font-size:1.3em;font-weight:600;}
.header .sub{font-size:.75em;color:#9fc4e6;margin-top:2px;}
.live{display:flex;align-items:center;gap:7px;font-size:.78em;color:#9fc4e6;}
.dot{width:9px;height:9px;border-radius:50%;background:var(--green);
box-shadow:0 0 7px var(--green);animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:.4;}}
.status{display:flex;gap:24px;background:var(--panel);padding:10px 20px;
border-radius:7px;margin-bottom:14px;font-size:.83em;border:1px solid var(--border);}
.status span{color:var(--muted);}
.status strong{color:var(--text);margin-left:5px;}
.tabs{display:flex;gap:3px;margin-bottom:14px;}
.tab{padding:9px 20px;background:var(--panel);border:1px solid var(--border);
border-radius:8px 8px 0 0;cursor:pointer;color:var(--muted);font-size:.88em;}
.tab.active{background:var(--p2);color:var(--blue);
border-bottom:2px solid var(--blue);font-weight:600;}
.view{display:none;}.view.active{display:block;}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;}
.card{background:var(--panel);padding:20px;border-radius:9px;
border:1px solid var(--border);position:relative;overflow:hidden;}
.card::before{content:'';position:absolute;left:0;top:0;width:4px;height:100%;}
.card.total::before{background:var(--blue);}
.card.allowed::before{background:var(--green);}
.card.blocked::before{background:var(--red);}
.card.rate::before{background:var(--amber);}
.card .num{font-size:2.1em;font-weight:700;line-height:1;}
.card .lbl{font-size:.78em;color:var(--muted);margin-top:7px;
text-transform:uppercase;letter-spacing:.5px;}
.card.total .num{color:var(--blue);}
.card.allowed .num{color:var(--green);}
.card.blocked .num{color:var(--red);}
.card.rate .num{color:var(--amber);}
.panel-box{background:var(--panel);border-radius:9px;
border:1px solid var(--border);margin-bottom:16px;overflow:hidden;}
.panel-head{padding:12px 18px;background:var(--p2);font-weight:600;
font-size:.9em;border-bottom:1px solid var(--border);}
.panel-body{padding:18px;}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:24px;}
.chart-title{font-size:.8em;color:var(--muted);margin-bottom:10px;
text-transform:uppercase;letter-spacing:.4px;}
.bar-row{display:flex;align-items:center;margin-bottom:9px;font-size:.86em;}
.bar-lbl{width:90px;color:var(--muted);}
.bar-track{flex:1;height:20px;background:var(--bg);border-radius:3px;
overflow:hidden;margin:0 10px;}
.bar-fill{height:100%;border-radius:3px;transition:width .5s ease;min-width:2px;}
.bar-val{width:28px;text-align:right;font-weight:600;}
.controls{display:flex;gap:9px;margin-bottom:12px;flex-wrap:wrap;}
.controls input,.controls select{background:var(--panel);
border:1px solid var(--border);color:var(--text);padding:8px 12px;
border-radius:6px;font-size:.86em;font-family:inherit;}
.controls input{flex:1;min-width:180px;}
.controls input:focus,.controls select:focus{outline:none;border-color:var(--blue);}
.tbl-wrap{background:var(--panel);border-radius:9px;
border:1px solid var(--border);overflow:hidden;}
table{width:100%;border-collapse:collapse;font-size:.82em;}
thead th{background:var(--p2);padding:11px 12px;text-align:left;
color:var(--muted);font-weight:600;position:sticky;top:0;
cursor:pointer;user-select:none;}
thead th:hover{color:var(--text);}
tbody td{padding:9px 12px;border-bottom:1px solid var(--border);
font-family:'Consolas',monospace;}
tbody tr:hover{background:var(--p2);}
.tbl-scroll{max-height:500px;overflow-y:auto;}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;
font-size:.8em;font-weight:600;}
.b-block{background:rgba(224,85,85,.18);color:#ff8080;}
.b-allow{background:rgba(63,185,104,.18);color:#6fd995;}
.b-sqli{background:rgba(224,85,85,.15);color:#ff9090;}
.b-xss{background:rgba(224,168,56,.15);color:#ffc860;}
.b-path{background:rgba(63,185,104,.15);color:#7fd9a5;}
.b-none{color:var(--muted);}
.empty{text-align:center;color:var(--muted);padding:36px;font-style:italic;}
.footer{text-align:center;font-size:.74em;color:#556677;margin-top:20px;}

.link{color:var(--blue);cursor:pointer;text-decoration:underline;}
tbody tr{cursor:pointer;}
.ov{position:fixed;inset:0;background:rgba(3,8,15,.66);display:none;
align-items:center;justify-content:center;padding:20px;z-index:50;}
.ov.show{display:flex;}
.modal{background:var(--panel);border:1px solid var(--border);border-radius:10px;
max-width:640px;width:100%;max-height:86vh;overflow:auto;}
.modal-head{display:flex;justify-content:space-between;align-items:center;
padding:14px 18px;background:var(--p2);border-bottom:1px solid var(--border);
border-radius:10px 10px 0 0;}
.modal-head h3{font-size:1em;font-weight:600;}
.modal-x{cursor:pointer;color:var(--muted);font-size:1.35em;line-height:1;}
.modal-body{padding:18px;}
.kv{display:grid;grid-template-columns:130px 1fr;gap:6px 12px;font-size:.86em;margin-bottom:12px;}
.kv .k{color:var(--muted);}
.payload-box{background:var(--bg);border:1px solid var(--border);border-radius:6px;
padding:11px;font-family:'Consolas',monospace;font-size:.82em;word-break:break-all;color:var(--text);}
.reason-box{background:rgba(224,168,56,.10);border:1px solid rgba(224,168,56,.35);
border-radius:6px;padding:11px;font-size:.86em;margin-top:6px;line-height:1.5;}
.sec{font-size:.76em;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin:14px 0 7px;}
</style></head><body>
<div class="wrap">
<div class="header">
  <div>
    <h1>Hybrid WAF Console</h1>
    <div class="sub">IT28X87 Honours Project &mdash; Mbadaliga, AB (219044112)</div>
  </div>
  <div class="live">
    <span class="dot"></span>
    <span>Live &mdash; refreshed <span id="upd">--:--:--</span></span>
  </div>
</div>
<div class="status">
  <div><span>Mode:</span><strong id="s-mode">hybrid</strong></div>
  <div><span>Pipeline:</span><strong>lr</strong></div>
  <div><span>Threshold:</span><strong>0.5</strong></div>
  <div><span>Log rows:</span><strong id="s-rows">0</strong></div>
</div>
<div class="tabs">
  <div class="tab active" onclick="showView('overview',this)">Overview</div>
  <div class="tab" onclick="showView('logs',this)">Log Explorer</div>
</div>
<div id="overview" class="view active">
  <div class="cards">
    <div class="card total"><div class="num" id="c-total">0</div><div class="lbl">Total Requests</div></div>
    <div class="card allowed"><div class="num" id="c-allowed">0</div><div class="lbl">Allowed</div></div>
    <div class="card blocked"><div class="num" id="c-blocked">0</div><div class="lbl">Blocked</div></div>
    <div class="card rate"><div class="num" id="c-rate">0%</div><div class="lbl">Block Rate</div></div>
  </div>
  <div class="panel-box">
    <div class="panel-head">Block Analysis</div>
    <div class="panel-body two-col">
      <div><div class="chart-title">By Attack Category</div><div id="cat-bars"></div></div>
      <div><div class="chart-title">By Trigger Type</div><div id="trig-bars"></div></div>
    </div>
  </div>
  <div class="panel-box">
    <div class="panel-head">Performance (entrance to decision, in-process time only)</div>
    <div class="panel-body">
      <div class="cards" style="margin-bottom:14px;">
        <div class="card total"><div class="num" id="p-avg">0</div><div class="lbl">Avg Total (ms)</div></div>
        <div class="card allowed"><div class="num" id="p-min">0</div><div class="lbl">Shortest (ms)</div></div>
        <div class="card blocked"><div class="num" id="p-max">0</div><div class="lbl">Longest (ms)</div></div>
        <div class="card rate"><div class="num" id="p-count">0</div><div class="lbl">Requests Timed</div></div>
      </div>
      <div class="chart-title">Average Time by Pipeline Stage</div>
      <div id="perf-bars"></div>
    </div>
  </div>
</div>
<div id="logs" class="view">
  <div class="controls">
    <input type="text" id="search" placeholder="Search path, IP, rule, reason..." oninput="renderTable()">
    <select id="f-action" onchange="renderTable()">
      <option value="">All actions</option>
      <option value="BLOCK">Blocked only</option>
      <option value="ALLOW">Allowed only</option>
    </select>
    <select id="f-cat" onchange="renderTable()">
      <option value="">All categories</option>
      <option value="SQLi">SQLi</option>
      <option value="XSS">XSS</option>
      <option value="PATH">Path Traversal</option>
    </select>
  </div>
  <div class="tbl-wrap">
    <div class="tbl-scroll">
      <table>
        <thead><tr>
          <th onclick="sortBy('timestamp')">Time</th>
          <th onclick="sortBy('source_ip')">Source IP</th>
          <th onclick="sortBy('method')">Method</th>
          <th onclick="sortBy('path')">Path</th>
          <th onclick="sortBy('action')">Action</th>
          <th onclick="sortBy('rule_category')">Category</th>
          <th onclick="sortBy('rule_id')">Rule</th>
          <th onclick="sortBy('ml_score')">ML Score</th>
          <th>Details</th>
        </tr></thead>
        <tbody id="log-body"></tbody>
      </table>
      <div id="log-empty" class="empty" style="display:none;">No matching log entries</div>
    </div>
  </div>
</div>
<div id="ov" class="ov" onclick="if(event.target===this)closeDetail()">
  <div class="modal">
    <div class="modal-head"><h3 id="m-title">Request detail</h3>
      <span class="modal-x" onclick="closeDetail()">&times;</span></div>
    <div class="modal-body" id="m-body"></div>
  </div>
</div>
<div class="footer">Hybrid WAF Console &mdash; auto-refreshes every 5 seconds</div>
</div>
<script>
let allRows=[],renderedRows=[],sortField='timestamp',sortDesc=true;
function showView(id,el){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById(id).classList.add('active');el.classList.add('active');
}
function bar(label,value,max,cls){
  const pct=max>0?(value/max*100):0;
  return`<div class="bar-row"><span class="bar-lbl">${label}</span>
  <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:var(--${cls})"></div></div>
  <span class="bar-val">${value}</span></div>`;
}
function renderOverview(s){
  document.getElementById('c-total').textContent=s.total;
  document.getElementById('c-allowed').textContent=s.allowed;
  document.getElementById('c-blocked').textContent=s.blocked;
  document.getElementById('c-rate').textContent=s.block_rate;
  document.getElementById('s-mode').textContent=s.mode;
  document.getElementById('s-rows').textContent=s.total;
  document.getElementById('upd').textContent=s.last_updated;
  const cat=s.by_category,cMax=Math.max(cat.SQLi,cat.XSS,cat.PATH,1);
  document.getElementById('cat-bars').innerHTML=
    bar('SQLi',cat.SQLi,cMax,'red')+bar('XSS',cat.XSS,cMax,'amber')+bar('Path Trav',cat.PATH,cMax,'green');
  const tr=s.by_trigger,tMax=Math.max(tr['Case A'],tr['Case B'],tr['Both agree'],1);
  document.getElementById('trig-bars').innerHTML=
    bar('Case A',tr['Case A'],tMax,'blue')+bar('Case B',tr['Case B'],tMax,'purple')+bar('Both agree',tr['Both agree'],tMax,'red');
  const p=s.perf||{};
  document.getElementById('p-avg').textContent=(p.avg_total_ms||0).toFixed(2);
  document.getElementById('p-min').textContent=(p.min_total_ms||0).toFixed(2);
  document.getElementById('p-max').textContent=(p.max_total_ms||0).toFixed(2);
  document.getElementById('p-count').textContent=p.count||0;
  const stageMax=Math.max(p.avg_extract_ms||0,p.avg_rule_ms||0,p.avg_ml_ms||0,p.avg_decide_ms||0,0.001);
  document.getElementById('perf-bars').innerHTML=
    bar('Extract',(p.avg_extract_ms||0).toFixed(3),stageMax,'blue')+
    bar('Rules',(p.avg_rule_ms||0).toFixed(3),stageMax,'green')+
    bar('ML',(p.avg_ml_ms||0).toFixed(3),stageMax,'purple')+
    bar('Decide',(p.avg_decide_ms||0).toFixed(3),stageMax,'amber');
}
function catBadge(cat){
  if(cat==='SQLi')return'<span class="badge b-sqli">SQLi</span>';
  if(cat==='XSS')return'<span class="badge b-xss">XSS</span>';
  if(cat==='PATH')return'<span class="badge b-path">Path</span>';
  return'<span class="b-none">-</span>';
}

function esc(x){return (x==null?'':String(x)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function openDetail(i){
  const r=renderedRows[i]; if(!r) return;
  const s=parseFloat(r.ml_score||0).toFixed(4);
  const blocked=r.action==='BLOCK';
  const badge=blocked?'<span class="badge b-block">BLOCK</span>':'<span class="badge b-allow">ALLOW</span>';
  let why=r.reason||'';
  if(blocked) why+=`  (ML score ${s}, threshold 0.5)`;
  else why=`No rule matched and the ML score ${s} is below the 0.5 threshold.`;
  const feats=[['F1 length',r.F1],['F2 special chars',r.F2],['F3 sql keywords',r.F3],
               ['F4 script flag',r.F4],['F5 traversal',r.F5],['F6 entropy',r.F6]];
  let fv='';
  for(const [k,v] of feats){ if(v!==undefined) fv+=`<div class="k">${k}</div><div>${esc(v)}</div>`; }
  let timingBlock='';
  if(r.t_total_ms){
    timingBlock = `<div class="sec">Processing Time (entrance to decision)</div>
     <div class="kv">
       <div class="k">Feature extraction</div><div>${esc(r.t_extract_ms)} ms</div>
       <div class="k">Rule engine</div><div>${esc(r.t_rule_ms)} ms</div>
       <div class="k">ML classifier</div><div>${esc(r.t_ml_ms)} ms</div>
       <div class="k">Decision engine</div><div>${esc(r.t_decide_ms)} ms</div>
       <div class="k"><strong>Total</strong></div><div><strong>${esc(r.t_total_ms)} ms</strong></div>
     </div>`;
  }
  document.getElementById('m-title').textContent = blocked?'Blocked request':'Allowed request';
  document.getElementById('m-body').innerHTML =
    `<div class="kv">
       <div class="k">Time</div><div>${esc((r.timestamp||'').replace('T',' ').substring(0,19))}</div>
       <div class="k">Action</div><div>${badge} ${catBadge(r.rule_category)}</div>
       <div class="k">Method</div><div>${esc(r.method||'')}</div>
       <div class="k">Rule</div><div>${esc(r.rule_id||'NONE')}</div>
       <div class="k">ML score</div><div>${s}</div>
     </div>
     <div class="sec">Payload</div>
     <div class="payload-box">${esc(r.payload || r.path || '')}</div>
     <div class="sec">Why this decision</div>
     <div class="reason-box">${esc(why)}</div>
     <div class="sec">Feature vector</div>
     <div class="kv">${fv}</div>
     ${timingBlock}`;
  document.getElementById('ov').classList.add('show');
}
function closeDetail(){document.getElementById('ov').classList.remove('show');}
function renderTable(){
  const q=document.getElementById('search').value.toLowerCase();
  const fa=document.getElementById('f-action').value;
  const fc=document.getElementById('f-cat').value;
  let rows=allRows.filter(r=>{
    if(fa&&r.action!==fa)return false;
    if(fc&&r.rule_category!==fc)return false;
    if(q){const hay=`${r.payload||''} ${r.path||''} ${r.source_ip||''} ${r.rule_id||''} ${r.reason||''} ${r.method||''}`.toLowerCase();if(!hay.includes(q))return false;}
    return true;
  });
  rows.sort((a,b)=>{
    let va=a[sortField]||'',vb=b[sortField]||'';
    if(sortField==='ml_score'){va=parseFloat(va)||0;vb=parseFloat(vb)||0;}
    if(va<vb)return sortDesc?1:-1;if(va>vb)return sortDesc?-1:1;return 0;
  });
  const body=document.getElementById('log-body');
  const empty=document.getElementById('log-empty');
  if(!rows.length){body.innerHTML='';empty.style.display='block';return;}
  empty.style.display='none';
  renderedRows=rows;
  body.innerHTML=rows.map((r,i)=>{
    const t=(r.timestamp||'').replace('T',' ').substring(0,19);
    const action=r.action==='BLOCK'?'<span class="badge b-block">BLOCK</span>':'<span class="badge b-allow">ALLOW</span>';
    const rule=(r.rule_id&&r.rule_id!=='NONE')?r.rule_id:'<span class="b-none">-</span>';
    const score=parseFloat(r.ml_score||0).toFixed(3);
    const sc=parseFloat(r.ml_score||0)>=0.5?'var(--red)':'var(--muted)';
    return`<tr onclick="openDetail(${i})"><td>${t}</td><td>${r.source_ip||''}</td><td>${r.method||''}</td><td>${esc(r.payload||r.path||'')}</td><td>${action}</td><td>${catBadge(r.rule_category)}</td><td>${rule}</td><td style="color:${sc}">${score}</td><td><span class="link">view</span></td></tr>`;
  }).join('');
}
function sortBy(f){if(sortField===f)sortDesc=!sortDesc;else{sortField=f;sortDesc=true;}renderTable();}
async function refresh(){
  try{
    const res=await fetch('/api/data');
    const data=await res.json();
    allRows=data.rows;renderOverview(data.stats);renderTable();
  }catch(e){console.error('refresh failed',e);}
}
refresh();setInterval(refresh,5000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/data":
            rows = read_rows(LOG_FILE)
            stats = compute_stats(rows)
            body = json.dumps({"stats": stats, "rows": rows}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(PAGE.encode())

    def log_message(self, *args):
        pass  # keep console clean during demo


def main():
    print(f"[Dashboard] Hybrid WAF Console")
    print(f"[Dashboard] http://localhost:{DASHBOARD_PORT}")
    print(f"[Dashboard] Log: {LOG_FILE}")
    print(f"[Dashboard] Ctrl+C to stop\n")
    server = HTTPServer(("0.0.0.0", DASHBOARD_PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Dashboard] Stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
