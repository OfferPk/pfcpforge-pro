/**
 * PFCPForge Pro - 10-Point Zero-Trust 5G N4 & 4G CUPS Security Auditor
 * Evaluates 3GPP TS 29.244 / TS 33.501 security posture, rule isolation,
 * buffer sizing, and transport hardening.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PFCPSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function auditPFCPSecurity(cfg) {
    const findings = [];
    let totalScore = 0;

    // Check 1: IPsec ESP / WireGuard Cryptographic Transport Encryption (TS 33.501) (12 pts)
    if (cfg.encryptionEnabled) {
      findings.push({
        id: 'IPSEC_ENC',
        name: 'N4 Cryptographic Transport Encryption (TS 33.501)',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: 'IPsec ESP or WireGuard tunnel active on UDP port 8805. Prevents MITM session tampering and GTP-U traffic redirection.',
        remediation: null
      });
      totalScore += 12;
    } else {
      findings.push({
        id: 'IPSEC_ENC',
        name: 'N4 Cryptographic Transport Encryption (TS 33.501)',
        score: 0,
        maxScore: 12,
        status: 'FAIL',
        description: 'CRITICAL HAZARD: Plaintext PFCP signaling on UDP 8805. Attackers can inject rogue FAR forwarding rules to siphon subscriber traffic.',
        remediation: 'Mandate IPsec IKEv2 ESP (AES-256-GCM) or WireGuard between SMF and UPF endpoints per 3GPP TS 33.501 Section 9.3.'
      });
    }

    // Check 2: F-SEID State Machine & Collision Isolation (64-bit) (12 pts)
    if (cfg.seidIsolationEnabled) {
      findings.push({
        id: 'SEID_ISOL',
        name: 'F-SEID 64-Bit State Machine & Collision Isolation',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: 'Randomized 64-bit SEID allocation bound to SMF IPv4/IPv6 address. Prevents cross-tenant session collision and memory leaks.',
        remediation: null
      });
      totalScore += 12;
    } else {
      findings.push({
        id: 'SEID_ISOL',
        name: 'F-SEID 64-Bit State Machine & Collision Isolation',
        score: 3,
        maxScore: 12,
        status: 'FAIL',
        description: 'Sequential or unisolated SEID allocation detected. High-concurrency session storms cause SEID collisions and context overwrite.',
        remediation: 'Implement cryptographic CSPRNG 64-bit SEID generator with hash-indexed session context verification in UPF.'
      });
      totalScore += 3;
    }

    // Check 3: PDR Precedence Disambiguation & Overlap Prevention (10 pts)
    if (cfg.precedenceEnforced) {
      findings.push({
        id: 'PDR_PREC',
        name: 'PDR Precedence Disambiguation & Overlap Filtering',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'Strict hierarchical precedence ordering configured. Eliminates non-deterministic packet classification in UPF DPDK/VPP pipelines.',
        remediation: null
      });
      totalScore += 10;
    } else {
      findings.push({
        id: 'PDR_PREC',
        name: 'PDR Precedence Disambiguation & Overlap Filtering',
        score: 2,
        maxScore: 10,
        status: 'WARN',
        description: 'Default identical precedence values used across overlapping PDR rules. Packet flow direction may become non-deterministic.',
        remediation: 'Assign discrete precedence levels: Emergency=10, VoNR IMS=50, Specific App SDF=100, Default Internet=255.'
      });
      totalScore += 2;
    }

    // Check 4: FAR Downlink Buffering & Memory Protection (NOCP/BUFF) (10 pts)
    const dlBufTimeout = parseFloat(cfg.bufferTimeoutSec) || 5;
    const maxBufPkts = parseInt(cfg.maxBufferPackets, 10) || 50;
    if (cfg.bufferingProtectionEnabled && dlBufTimeout <= 10 && maxBufPkts <= 100) {
      findings.push({
        id: 'FAR_BUF',
        name: 'Downlink Data Buffering & OOM Protection',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: `Downlink buffer capped at ${maxBufPkts} packets per UE with ${dlBufTimeout}s timeout. Protects UPF kernel RAM from exhaustion during paging.`,
        remediation: null
      });
      totalScore += 10;
    } else if (cfg.bufferingProtectionEnabled) {
      findings.push({
        id: 'FAR_BUF',
        name: 'Downlink Data Buffering & OOM Protection',
        score: 6,
        maxScore: 10,
        status: 'WARN',
        description: `Buffering timeout (${dlBufTimeout}s) or packet limit (${maxBufPkts}) is generous. Burst paging traffic risks UPF buffer exhaustion.`,
        remediation: 'Cap DL Buffering Duration to <= 5 seconds and maximum buffered packets to 50 packets per idle session.'
      });
      totalScore += 6;
    } else {
      findings.push({
        id: 'FAR_BUF',
        name: 'Downlink Data Buffering & OOM Protection',
        score: 0,
        maxScore: 10,
        status: 'FAIL',
        description: 'Unbounded downlink buffering! Malicious TCP syn floods to idle UEs will trigger UPF out-of-memory kernel panic.',
        remediation: 'Configure explicit DL Buffering Suggested Packet Count (IE 140) and drop buffer on paging timeout.'
      });
    }

    // Check 5: QER Gate & 5QI/QFI Rate Enforcement (10 pts)
    if (cfg.qerEnforced) {
      findings.push({
        id: 'QER_RATE',
        name: 'QER 5QI/QFI Bandwidth & Gate Enforcement',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'Hardware token-bucket policing enforced per QFI (MBR/GBR). Voice (5QI 1) prioritized and rogue bandwidth consumption curtailed.',
        remediation: null
      });
      totalScore += 10;
    } else {
      findings.push({
        id: 'QER_RATE',
        name: 'QER 5QI/QFI Bandwidth & Gate Enforcement',
        score: 2,
        maxScore: 10,
        status: 'FAIL',
        description: 'Missing or unpoliced QER rules. Malicious UE can saturate SGi/N6 links and starve VoNR IMS voice bearers.',
        remediation: 'Enforce QER MBR policing on Access interface and configure Gate Status = CLOSED for suspended bearers.'
      });
      totalScore += 2;
    }

    // Check 6: N4 Association Heartbeat & Node Failure Recovery (10 pts)
    const hbInterval = parseInt(cfg.heartbeatIntervalSec, 10) || 10;
    if (cfg.heartbeatEnabled && hbInterval <= 15) {
      findings.push({
        id: 'N4_HB',
        name: 'N4 Association Heartbeat & Recovery Timestamp',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: `Periodic Heartbeat (${hbInterval}s) with Recovery Time Stamp verification. Instant failover upon UPF or SMF restart.`,
        remediation: null
      });
      totalScore += 10;
    } else if (cfg.heartbeatEnabled) {
      findings.push({
        id: 'N4_HB',
        name: 'N4 Association Heartbeat & Recovery Timestamp',
        score: 6,
        maxScore: 10,
        status: 'WARN',
        description: `Heartbeat interval (${hbInterval}s) is sluggish. Node failure detection will lag, resulting in blackholed subscriber sessions.`,
        remediation: 'Tune PFCP Heartbeat interval to 5–10 seconds with 3 retries (RFC 3539 behavior).'
      });
      totalScore += 6;
    } else {
      findings.push({
        id: 'N4_HB',
        name: 'N4 Association Heartbeat & Recovery Timestamp',
        score: 1,
        maxScore: 10,
        status: 'FAIL',
        description: 'Heartbeat disabled! Crashed UPF nodes remain registered in SMF, leading to 100% session setup failure.',
        remediation: 'Enable Heartbeat Request/Response (Types 1/2) with Recovery Timestamp parsing in smf.yaml / upf.yaml.'
      });
      totalScore += 1;
    }

    // Check 7: URR Volume Quota & Event Telemetry Isolation (10 pts)
    if (cfg.urrAccountingEnabled) {
      findings.push({
        id: 'URR_ACCT',
        name: 'URR Charging Telemetry & Quota Enforcement',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'Multi-trigger URR volume monitoring (Volume Threshold + Quota Exhaustion). Prevents postpaid revenue leakage.',
        remediation: null
      });
      totalScore += 10;
    } else {
      findings.push({
        id: 'URR_ACCT',
        name: 'URR Charging Telemetry & Quota Enforcement',
        score: 2,
        maxScore: 10,
        status: 'WARN',
        description: 'URR accounting disabled or unmetered. Subscriber usage data is unrecorded over N4 interface.',
        remediation: 'Configure URR with Volume Threshold trigger (Reporting Triggers bit 2) and quota exhaustion report.'
      });
      totalScore += 2;
    }

    // Check 8: Ingress PDI Anti-IP Spoofing Protection (9 pts)
    if (cfg.antiSpoofingEnabled) {
      findings.push({
        id: 'PDI_SPOOF',
        name: 'Ingress PDI Interface Anti-IP Spoofing',
        score: 9,
        maxScore: 9,
        status: 'PASS',
        description: 'Access PDR strictly verifies Source IPv4 matches UE IP Address assigned by SMF. Drops rogue spoofed packets at ingress.',
        remediation: null
      });
      totalScore += 9;
    } else {
      findings.push({
        id: 'PDI_SPOOF',
        name: 'Ingress PDI Interface Anti-IP Spoofing',
        score: 2,
        maxScore: 9,
        status: 'FAIL',
        description: 'Loose PDR matching. UEs can inject packets with arbitrary source IPs, enabling internal core network spoofing.',
        remediation: 'Include UE IP Address IE (Type 93) in Access interface PDI to enforce strict source address verification.'
      });
      totalScore += 2;
    }

    // Check 9: Redundant SMF/UPF Association & Load-Balancing (9 pts)
    if (cfg.redundancyEnabled) {
      findings.push({
        id: 'N4_REDUND',
        name: 'SMF/UPF N4 Redundancy & Load-Balancing',
        score: 9,
        maxScore: 9,
        status: 'PASS',
        description: 'Multi-UPF pool configured with dynamic load metric weighting and seamless session migration.',
        remediation: null
      });
      totalScore += 9;
    } else {
      findings.push({
        id: 'N4_REDUND',
        name: 'SMF/UPF N4 Redundancy & Load-Balancing',
        score: 3,
        maxScore: 9,
        status: 'WARN',
        description: 'Single UPF association. A maintenance reboot or hardware fault severs all active user data sessions.',
        remediation: 'Deploy dual UPF instances with SMF user-plane selection algorithm based on UPF Load and Availability.'
      });
      totalScore += 3;
    }

    // Check 10: Control Plane Policing (CoPP) for UDP Port 8805 (8 pts)
    if (cfg.coppEnabled) {
      findings.push({
        id: 'N4_COPP',
        name: 'Control Plane Policing (CoPP) for UDP 8805',
        score: 8,
        maxScore: 8,
        status: 'PASS',
        description: 'Hardware firewall and policer active on UDP port 8805. Mitigates volumetric signaling floods against UPF control core.',
        remediation: null
      });
      totalScore += 8;
    } else {
      findings.push({
        id: 'N4_COPP',
        name: 'Control Plane Policing (CoPP) for UDP 8805',
        score: 0,
        maxScore: 8,
        status: 'FAIL',
        description: 'No CoPP rate-limiting on N4 UDP port 8805. Susceptible to control plane CPU starvation.',
        remediation: 'Install CoPP policer limiting UDP 8805 to 50,000 pps with strict IP source filtering.'
      });
    }

    // Grading Scale
    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 90) grade = 'A';
    else if (totalScore >= 80) grade = 'B';
    else if (totalScore >= 70) grade = 'C';
    else if (totalScore >= 60) grade = 'D';

    const passed = totalScore >= 80;
    let summary = '';
    if (grade === 'A+' || grade === 'A') {
      summary = 'Production-grade 5G N4 / 4G CUPS signaling architecture with IPsec transport encryption, strict PDR/FAR/QER rule isolation, and buffer protection.';
    } else if (grade === 'B') {
      summary = 'Acceptable baseline security, but minor gaps exist in heartbeat tuning, redundancy, or buffer packet caps.';
    } else {
      summary = 'High operational and security risk! Unencrypted N4 signaling, loose AVP filtering, or unbounded buffering expose the core network to hijacking and outages.';
    }

    return {
      totalScore,
      maxScore: 100,
      grade,
      passed,
      summary,
      findings
    };
  }

  return {
    auditPFCPSecurity
  };
}));
