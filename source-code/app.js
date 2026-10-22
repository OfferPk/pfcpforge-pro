/**
 * PFCPForge Pro - Web Application Controller
 */

(function () {
  'use strict';

  // Industry Presets
  const PRESETS = {
    carrier: {
      name: 'Carrier 5G SA Core N4 (Grade A+)',
      msgType: 50,
      seidHex: '0x0000000000000001',
      smfNodeId: 'smf01.carrier.5g',
      smfIp: '10.200.1.10',
      upfIp: '10.200.1.20',
      gnbIp: '198.51.100.10',
      ueIp: '10.45.0.2',
      dnn: 'internet',
      qfi: 9,
      uplinkTeid: 305419896,
      downlinkTeid: 2271560481,
      mbrDlKbps: 1000000,
      mbrUlKbps: 100000,
      ueIdle: false,
      bufferTimeoutSec: 5,
      maxBufferPackets: 50,
      idleUeCount: 5000,
      activeSessions: 50000,
      encryptionEnabled: true,
      seidIsolationEnabled: true,
      precedenceEnforced: true,
      bufferingProtectionEnabled: true,
      qerEnforced: true,
      heartbeatEnabled: true,
      heartbeatIntervalSec: 10,
      urrAccountingEnabled: true,
      antiSpoofingEnabled: true,
      redundancyEnabled: true,
      coppEnabled: true
    },
    private: {
      name: 'Private 5G MEC Edge UPF (Grade A)',
      msgType: 50,
      seidHex: '0x000000000000A100',
      smfNodeId: 'smf.factory.priv5g',
      smfIp: '192.168.10.5',
      upfIp: '192.168.10.2',
      gnbIp: '192.168.20.100',
      ueIp: '10.100.0.5',
      dnn: 'edge-compute',
      qfi: 5, // Low-latency industrial automation
      uplinkTeid: 11223344,
      downlinkTeid: 55667788,
      mbrDlKbps: 500000,
      mbrUlKbps: 500000,
      ueIdle: false,
      bufferTimeoutSec: 3,
      maxBufferPackets: 30,
      idleUeCount: 200,
      activeSessions: 2000,
      encryptionEnabled: true,
      seidIsolationEnabled: true,
      precedenceEnforced: true,
      bufferingProtectionEnabled: true,
      qerEnforced: true,
      heartbeatEnabled: true,
      heartbeatIntervalSec: 5,
      urrAccountingEnabled: true,
      antiSpoofingEnabled: true,
      redundancyEnabled: false, // Single edge site UPF
      coppEnabled: true
    },
    vulnerable: {
      name: 'Vulnerable Unencrypted N4 (Grade F)',
      msgType: 50,
      seidHex: '0x0000000000000001',
      smfNodeId: 'core-smf.net',
      smfIp: '172.16.0.10',
      upfIp: '172.16.0.20',
      gnbIp: '203.0.113.50',
      ueIp: '10.88.0.2',
      dnn: 'default',
      qfi: 9,
      uplinkTeid: 1001,
      downlinkTeid: 2002,
      mbrDlKbps: 1000000,
      mbrUlKbps: 100000,
      ueIdle: true, // Paging
      bufferTimeoutSec: 60, // Unbounded!
      maxBufferPackets: 1000, // Massive!
      idleUeCount: 20000,
      activeSessions: 100000,
      encryptionEnabled: false, // Plaintext!
      seidIsolationEnabled: false, // Collision risk!
      precedenceEnforced: false, // Overlapping rules!
      bufferingProtectionEnabled: false, // OOM crash!
      qerEnforced: false, // Unmetered!
      heartbeatEnabled: false, // No failover!
      urrAccountingEnabled: false,
      antiSpoofingEnabled: false,
      redundancyEnabled: false,
      coppEnabled: false
    }
  };

  let activeTab = 'open5gs';

  // DOM Elements
  const elMsgType = document.getElementById('select-msg-type');
  const elSeidHex = document.getElementById('input-seid-hex');
  const elSmfIp = document.getElementById('input-smf-ip');
  const elUpfIp = document.getElementById('input-upf-ip');
  const elGnbIp = document.getElementById('input-gnb-ip');
  const elUeIp = document.getElementById('input-ue-ip');
  const elDnn = document.getElementById('input-dnn');
  const elQfi = document.getElementById('input-qfi');

  const elUplinkTeid = document.getElementById('input-uplink-teid');
  const elDownlinkTeid = document.getElementById('input-downlink-teid');
  const elMbrDl = document.getElementById('input-mbr-dl');
  const elMbrUl = document.getElementById('input-mbr-ul');
  const elChkUeIdle = document.getElementById('chk-ue-idle');

  const elBufTimeout = document.getElementById('input-buf-timeout');
  const elMaxBufPkts = document.getElementById('input-max-buf-pkts');
  const elIdleUes = document.getElementById('input-idle-ues');
  const elActiveSessions = document.getElementById('input-active-sessions');

  const elBadgeMsgType = document.getElementById('badge-msg-type');
  const elBadgeBufferRisk = document.getElementById('badge-buffer-risk');
  const elTxtFarAction = document.getElementById('txt-far-action');

  const elChkEncryption = document.getElementById('chk-encryption');
  const elChkSeidIsolation = document.getElementById('chk-seid-isolation');
  const elChkPrecedence = document.getElementById('chk-precedence');
  const elChkBufferProtect = document.getElementById('chk-buffer-protect');
  const elChkQerEnforce = document.getElementById('chk-qer-enforce');
  const elChkHeartbeat = document.getElementById('chk-heartbeat');
  const elChkUrrAcct = document.getElementById('chk-urr-acct');
  const elChkAntiSpoof = document.getElementById('chk-anti-spoof');
  const elChkRedundancy = document.getElementById('chk-redundancy');
  const elChkCopp = document.getElementById('chk-copp');

  const elValDlBufferRam = document.getElementById('val-dl-buffer-ram');
  const elValSessionRam = document.getElementById('val-session-ram');
  const elValTotalUpfRam = document.getElementById('val-total-upf-ram');
  const elValAuthEnc = document.getElementById('val-auth-enc');

  const elScoreBanner = document.getElementById('score-banner');
  const elScoreGrade = document.getElementById('score-grade');
  const elScoreTitle = document.getElementById('score-title');
  const elScoreSummary = document.getElementById('score-summary');
  const elFindingsContainer = document.getElementById('findings-container');

  const elBadgePacketDesc = document.getElementById('badge-packet-desc');
  const elPacketHexDump = document.getElementById('packet-hex-dump');
  const elSynthOutput = document.getElementById('synth-output');
  const elBtnCopy = document.getElementById('btn-copy-config');

  function getFormConfig() {
    return {
      msgType: parseInt(elMsgType.value, 10) || 50,
      seidHex: elSeidHex.value.trim(),
      smfNodeId: 'smf01.carrier.5g',
      smfIp: elSmfIp.value.trim(),
      upfIp: elUpfIp.value.trim(),
      gnbIp: elGnbIp.value.trim(),
      ueIp: elUeIp.value.trim(),
      dnn: elDnn.value.trim(),
      qfi: parseInt(elQfi.value, 10) || 9,
      uplinkTeid: parseInt(elUplinkTeid.value, 10) || 305419896,
      downlinkTeid: parseInt(elDownlinkTeid.value, 10) || 2271560481,
      mbrDlKbps: parseInt(elMbrDl.value, 10) || 1000000,
      mbrUlKbps: parseInt(elMbrUl.value, 10) || 100000,
      ueIdle: elChkUeIdle.checked,
      bufferTimeoutSec: parseFloat(elBufTimeout.value) || 5,
      maxBufferPackets: parseInt(elMaxBufPkts.value, 10) || 50,
      idleUeCount: parseInt(elIdleUes.value, 10) || 5000,
      activeSessions: parseInt(elActiveSessions.value, 10) || 50000,
      encryptionEnabled: elChkEncryption.checked,
      seidIsolationEnabled: elChkSeidIsolation.checked,
      precedenceEnforced: elChkPrecedence.checked,
      bufferingProtectionEnabled: elChkBufferProtect.checked,
      qerEnforced: elChkQerEnforce.checked,
      heartbeatEnabled: elChkHeartbeat.checked,
      heartbeatIntervalSec: 10,
      urrAccountingEnabled: elChkUrrAcct.checked,
      antiSpoofingEnabled: elChkAntiSpoof.checked,
      redundancyEnabled: elChkRedundancy.checked,
      coppEnabled: elChkCopp.checked
    };
  }

  function applyPreset(presetKey) {
    const p = PRESETS[presetKey];
    if (!p) return;

    elMsgType.value = p.msgType;
    elSeidHex.value = p.seidHex;
    elSmfIp.value = p.smfIp;
    elUpfIp.value = p.upfIp;
    elGnbIp.value = p.gnbIp;
    elUeIp.value = p.ueIp;
    elDnn.value = p.dnn;
    elQfi.value = p.qfi;
    elUplinkTeid.value = p.uplinkTeid;
    elDownlinkTeid.value = p.downlinkTeid;
    elMbrDl.value = p.mbrDlKbps;
    elMbrUl.value = p.mbrUlKbps;
    elChkUeIdle.checked = p.ueIdle;
    elBufTimeout.value = p.bufferTimeoutSec;
    elMaxBufPkts.value = p.maxBufferPackets;
    elIdleUes.value = p.idleUeCount;
    elActiveSessions.value = p.activeSessions;

    elChkEncryption.checked = p.encryptionEnabled;
    elChkSeidIsolation.checked = p.seidIsolationEnabled;
    elChkPrecedence.checked = p.precedenceEnforced;
    elChkBufferProtect.checked = p.bufferingProtectionEnabled;
    elChkQerEnforce.checked = p.qerEnforced;
    elChkHeartbeat.checked = p.heartbeatEnabled;
    elChkUrrAcct.checked = p.urrAccountingEnabled;
    elChkAntiSpoof.checked = p.antiSpoofingEnabled;
    elChkRedundancy.checked = p.redundancyEnabled;
    elChkCopp.checked = p.coppEnabled;

    document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById(`btn-preset-${presetKey}`);
    if (btn) btn.classList.add('active');

    updateAll();
  }

  function updateAll() {
    const cfg = getFormConfig();

    // 1. Badge Message Type
    const msgInfo = PFCPProtocolEngine.MESSAGE_TYPES[cfg.msgType] || { name: 'PFCP Message', abbr: 'MSG' };
    elBadgeMsgType.textContent = `${msgInfo.name} (${cfg.msgType})`;

    // 2. Action Description
    if (cfg.ueIdle) {
      elTxtFarAction.textContent = 'BUFF (0x04) + NOCP (0x08)';
      elTxtFarAction.style.color = '#fbbf24';
    } else {
      elTxtFarAction.textContent = 'FORW (GTP-U Encaps)';
      elTxtFarAction.style.color = '#34d399';
    }

    // 3. Sizing Calculations
    const sizing = PFCPProtocolEngine.calculateBufferingSizing({
      dlBandwidthMbps: cfg.mbrDlKbps / 1000,
      bufferTimeoutSec: cfg.bufferTimeoutSec,
      idleUeCount: cfg.idleUeCount,
      activeSessions: cfg.activeSessions
    });

    elValDlBufferRam.textContent = `${(sizing.totalDlBufferRAM_MB / 1024).toFixed(2)} GB`;
    elValSessionRam.textContent = `${sizing.sessionContextRAM_MB} MB`;
    elValTotalUpfRam.textContent = `${sizing.totalUpfMemoryGB} GB`;
    elValAuthEnc.textContent = cfg.encryptionEnabled ? 'IPsec Active' : 'Plaintext (Insecure)';

    if (sizing.bufferOverheadRisk === 'CRITICAL_HIGH') {
      elBadgeBufferRisk.textContent = 'High OOM Risk';
      elBadgeBufferRisk.className = 'badge badge-rose';
    } else if (sizing.bufferOverheadRisk === 'MODERATE') {
      elBadgeBufferRisk.textContent = 'Moderate';
      elBadgeBufferRisk.className = 'badge badge-amber';
    } else {
      elBadgeBufferRisk.textContent = 'Optimal Buffer';
      elBadgeBufferRisk.className = 'badge badge-emerald';
    }

    // 4. 10-Point Zero-Trust Audit
    const audit = PFCPSecurityAuditor.auditPFCPSecurity(cfg);
    elScoreGrade.textContent = audit.grade;
    elScoreTitle.textContent = `${audit.totalScore} / ${audit.maxScore} Points (${audit.passed ? 'Passed' : 'Failed'})`;
    elScoreSummary.textContent = audit.summary;
    elScoreBanner.className = `score-badge-large ${audit.passed ? 'grade-A' : 'grade-F'}`;

    elFindingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const item = document.createElement('div');
      item.className = `finding-item ${f.status.toLowerCase()}`;
      item.innerHTML = `
        <div class="finding-title">
          <span>${f.name}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxScore} pts</span>
        </div>
        <div class="finding-desc">${f.description}</div>
        ${f.remediation ? `<div class="finding-remediation">Remediation: ${f.remediation}</div>` : ''}
      `;
      elFindingsContainer.appendChild(item);
    });

    // 5. Binary Packet Encoding & Hex Dissector
    const pktBytes = PFCPProtocolEngine.encodePFCPMessage(cfg);
    elBadgePacketDesc.textContent = `${msgInfo.name} (${pktBytes.length} Bytes)`;
    elPacketHexDump.textContent = PFCPProtocolEngine.formatHexDump(pktBytes);

    // 6. Synthesizer Output
    renderSynthesizer(cfg);
  }

  function renderSynthesizer(cfg) {
    let code = '';
    if (activeTab === 'open5gs') {
      code = PFCPConfigSynthesizer.generateOpen5GS(cfg);
    } else if (activeTab === 'free5gc') {
      code = PFCPConfigSynthesizer.generateFree5GC(cfg);
    } else if (activeTab === 'cisco') {
      code = PFCPConfigSynthesizer.generateCisco(cfg);
    } else if (activeTab === 'junos') {
      code = PFCPConfigSynthesizer.generateJunos(cfg);
    } else if (activeTab === 'prom') {
      code = PFCPConfigSynthesizer.generatePrometheus(cfg);
    }
    elSynthOutput.textContent = code;
  }

  // Event Listeners
  document.getElementById('btn-preset-carrier').addEventListener('click', () => applyPreset('carrier'));
  document.getElementById('btn-preset-private').addEventListener('click', () => applyPreset('private'));
  document.getElementById('btn-preset-vulnerable').addEventListener('click', () => applyPreset('vulnerable'));
  document.getElementById('btn-recalculate').addEventListener('click', updateAll);

  [elMsgType, elSeidHex, elSmfIp, elUpfIp, elGnbIp, elUeIp, elDnn, elQfi,
   elUplinkTeid, elDownlinkTeid, elMbrDl, elMbrUl, elChkUeIdle,
   elBufTimeout, elMaxBufPkts, elIdleUes, elActiveSessions,
   elChkEncryption, elChkSeidIsolation, elChkPrecedence, elChkBufferProtect,
   elChkQerEnforce, elChkHeartbeat, elChkUrrAcct, elChkAntiSpoof,
   elChkRedundancy, elChkCopp
  ].forEach(input => {
    input.addEventListener('change', updateAll);
  });

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      activeTab = e.target.getAttribute('data-tab');
      renderSynthesizer(getFormConfig());
    });
  });

  elBtnCopy.addEventListener('click', () => {
    navigator.clipboard.writeText(elSynthOutput.textContent).then(() => {
      elBtnCopy.textContent = 'Copied!';
      setTimeout(() => { elBtnCopy.textContent = 'Copy Config'; }, 2000);
    });
  });

  // Initialize
  applyPreset('carrier');
})();
