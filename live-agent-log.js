/*!
 * Live Agent Log — simulated terminal widget
 * Supports data-variant="preview" (compact, homepage)
 *        and data-variant="full"    (expanded, cyber page)
 */
(function () {
  'use strict';

  /* ── Scenario pools ────────────────────────────────────────────────────── */

  var PREVIEW_LINES = [
    '[INF] agent-monitor started  pid=1842',
    '[INF] loading detection ruleset v2.4.1',
    '[INF] connected to event bus  queue=sec-events',
    '[EVT] process spawn observed  parent=sshd  child=bash  user=ubuntu',
    '[INF] baseline profile cached  host=web-01',
    '[EVT] outbound DNS query  host=web-01  fqdn=api.threat-intel.io',
    '[INF] reputation lookup ok  score=2/100  verdict=clean',
    '[EVT] file write detected  path=/tmp/.cache  size=4096B',
    '[ALT] anomaly score elevated  host=web-01  score=62/100',
    '[INF] alert forwarded to SIEM  id=ALT-0042',
    '[INF] triage workflow triggered  playbook=auto-isolate-v1',
    '[EVT] lateral movement probe  src=10.0.0.22  dst=10.0.0.45  port=445',
    '[ALT] SMB scan pattern matched  confidence=HIGH',
    '[INF] network segment quarantined  vlan=prod-dmz',
    '[INF] analyst notified  channel=pagerduty',
    '[EVT] new agent enrolled  host=db-02  os=Ubuntu 22.04',
    '[INF] policy sync complete  rules=318',
    '[INF] idle  next heartbeat in 30s',
  ];

  var FULL_LINES = [
    '[BOOT] live-agent-log v1.0.0 initializing',
    '[INF] loading threat intel feeds  sources=3',
    '[INF] MITRE ATT&CK mapping loaded  techniques=196',
    '[INF] agent-monitor started  pid=2201  host=soc-prod-01',
    '[INF] connected to event bus  broker=kafka  topic=sec-raw-events',
    '[INF] baseline profiles loaded  hosts=47  users=212',
    '',
    '[EVT] T1078 — valid account login  user=svc_deploy  src=172.16.10.5  time=03:14Z',
    '[INF] off-hours login flagged  risk=medium  score=48/100',
    '[INF] context enrichment: last login 6 days ago from 172.16.10.3',
    '[ALT] risk score exceeded threshold  score=48 > 40  escalating',
    '',
    '[EVT] T1059.001 — PowerShell exec  host=ws-019  user=svc_deploy',
    '[ALT] obfuscated command detected  confidence=HIGH  ioc=base64-encoded-payload',
    '[INF] sandbox detonation queued  sample_id=SBX-0317',
    '[INF] sandbox result: MALICIOUS  family=Cobalt-Strike-beacon  score=94/100',
    '[ALT] severity=CRITICAL  killing process tree  pid=8841',
    '[INF] host ws-019 isolated from network  vlan=quarantine',
    '',
    '[RED] emulation scenario started  scenario=T1566.001-phishing  scope=lab-range',
    '[RED] payload delivered to canary inbox  target=canary@lab.internal',
    '[RED] user interaction simulated (authorized test)',
    '[RED] C2 beacon established  ip=198.51.100.14  port=443 (authorized range)',
    '[BLU] C2 traffic detected  rule=beacon-jitter-pattern  confidence=MED',
    '[BLU] IP 198.51.100.14 added to block list  source=auto-response',
    '[RED] emulation complete  detections=1/1  coverage=100%  ✓ guardrail active',
    '',
    '[EVT] T1021.002 — SMB lateral movement  src=ws-019  dst=db-01  port=445',
    '[ALT] movement blocked by quarantine policy — no pivot possible',
    '[INF] IR ticket created  id=INC-0058  priority=P1  team=SOC-Alpha',
    '',
    '[INF] daily report generated  alerts=12  incidents=1  MTTR=4m32s',
    '[INF] agent-monitor idle  next cycle in 60s',
  ];

  /* ── Helpers ────────────────────────────────────────────────────────────── */

  function colorLine(text) {
    if (!text) return '<br>';
    var escaped = text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    if (/^\[ALT\]/.test(text)) return '<span class="al-alert">' + escaped + '</span>';
    if (/^\[RED\]/.test(text)) return '<span class="al-red">' + escaped + '</span>';
    if (/^\[BLU\]/.test(text)) return '<span class="al-blue">' + escaped + '</span>';
    if (/^\[EVT\]/.test(text)) return '<span class="al-evt">' + escaped + '</span>';
    if (/^\[BOOT\]/.test(text)) return '<span class="al-boot">' + escaped + '</span>';
    return '<span class="al-info">' + escaped + '</span>';
  }

  /* ── Widget factory ─────────────────────────────────────────────────────── */

  function initWidget(container) {
    var variant = container.getAttribute('data-variant') || 'preview';
    var isFull = variant === 'full';

    var lines    = isFull ? FULL_LINES : PREVIEW_LINES;
    var maxLines = isFull ? 22 : 10;
    var tickMs   = isFull ? 900 : 1600;
    var titleTxt = isFull ? 'live-agent-log — soc-prod-01' : 'live-agent-log';

    /* Build DOM */
    var wrap = document.createElement('div');
    wrap.className = 'al-terminal' + (isFull ? ' al-terminal--full' : '');

    var topbar = document.createElement('div');
    topbar.className = 'al-topbar';
    topbar.innerHTML =
      '<span class="al-dot al-dot--red"></span>' +
      '<span class="al-dot al-dot--yellow"></span>' +
      '<span class="al-dot al-dot--green"></span>' +
      '<span class="al-topbar-title">' + titleTxt + '</span>' +
      '<span class="al-badge">LIVE</span>';

    var body = document.createElement('div');
    body.className = 'al-body';

    var output = document.createElement('div');
    output.className = 'al-output';
    output.setAttribute('aria-live', 'polite');
    output.setAttribute('aria-label', 'Simulated agent log output');

    var cursor = document.createElement('span');
    cursor.className = 'al-cursor';
    cursor.setAttribute('aria-hidden', 'true');

    body.appendChild(output);
    body.appendChild(cursor);
    wrap.appendChild(topbar);
    wrap.appendChild(body);
    container.appendChild(wrap);

    /* Ticker */
    var idx = 0;
    var displayed = [];
    var reducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function tick() {
      if (idx >= lines.length) {
        idx = 0;
        displayed = [];
        output.innerHTML = '';
      }

      var line = lines[idx++];
      var el = document.createElement('div');
      el.className = 'al-line';
      el.innerHTML = colorLine(line);
      output.appendChild(el);

      displayed.push(el);
      if (displayed.length > maxLines) {
        var old = displayed.shift();
        old.parentNode.removeChild(old);
      }

      /* auto-scroll */
      body.scrollTop = body.scrollHeight;

      var jitter = reducedMotion ? 0 : Math.random() * 400;
      setTimeout(tick, tickMs + jitter);
    }

    setTimeout(tick, 600);
  }

  /* ── Boot ───────────────────────────────────────────────────────────────── */

  function boot() {
    var containers = document.querySelectorAll('.al-widget');
    for (var i = 0; i < containers.length; i++) {
      initWidget(containers[i]);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
