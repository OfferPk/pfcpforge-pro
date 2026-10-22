/**
 * PFCPForge Pro - 3GPP TS 29.244 Protocol Engine
 * Models PFCP Binary Packets, PDR, FAR, QER, URR, and Sizing Calculations.
 * Compatible with Node.js and Browser environments.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PFCPProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // 3GPP TS 29.244 PFCP Message Types
  const MESSAGE_TYPES = {
    1: { name: 'Heartbeat Request', abbr: 'HBRQ', nodeType: 'SMF/UPF' },
    2: { name: 'Heartbeat Response', abbr: 'HBRS', nodeType: 'SMF/UPF' },
    5: { name: 'PFCP Association Setup Request', abbr: 'ASRQ', nodeType: 'SMF' },
    6: { name: 'PFCP Association Setup Response', abbr: 'ASRS', nodeType: 'UPF' },
    50: { name: 'PFCP Session Establishment Request', abbr: 'SEST', nodeType: 'SMF' },
    51: { name: 'PFCP Session Establishment Response', abbr: 'SERS', nodeType: 'UPF' },
    52: { name: 'PFCP Session Modification Request', abbr: 'SMOD', nodeType: 'SMF' },
    53: { name: 'PFCP Session Modification Response', abbr: 'SMRS', nodeType: 'UPF' },
    54: { name: 'PFCP Session Deletion Request', abbr: 'SDEL', nodeType: 'SMF' },
    55: { name: 'PFCP Session Deletion Response', abbr: 'SDRS', nodeType: 'UPF' },
    56: { name: 'PFCP Session Report Request', abbr: 'SRPT', nodeType: 'UPF' },
    57: { name: 'PFCP Session Report Response', abbr: 'SRRS', nodeType: 'SMF' }
  };

  // 3GPP TS 29.244 Information Element (IE) Types
  const IE_TYPES = {
    19: 'Cause',
    20: 'Source Interface',
    21: 'F-TEID',
    22: 'Network Instance',
    23: 'SDF Filter',
    25: 'Gate Status',
    29: 'Precedence',
    31: 'Volume Threshold',
    37: 'Reporting Triggers',
    42: 'Destination Interface',
    44: 'Apply Action',
    56: 'Create PDR',
    57: 'F-SEID',
    60: 'Node ID',
    62: 'Measurement Method',
    64: 'Measurement Period',
    72: 'Maximum Bitrate (MBR)',
    73: 'Guaranteed Bitrate (GBR)',
    81: 'Create URR',
    84: 'Outer Header Creation',
    93: 'UE IP Address',
    95: 'Outer Header Removal',
    96: 'Recovery Time Stamp',
    108: 'Create FAR',
    109: 'Create QER',
    124: 'QFI'
  };

  // Helper: Convert IPv4 string to 4-byte array
  function ipToBytes(ipStr) {
    const parts = ipStr.split('.').map(p => parseInt(p, 10) & 0xFF);
    return parts.length === 4 ? parts : [0, 0, 0, 0];
  }

  // Helper: Convert 64-bit integer (or hex string) to 8-byte array
  function seidToBytes(seidVal) {
    let hex = typeof seidVal === 'string' ? seidVal.replace(/^0x/i, '') : Number(seidVal).toString(16);
    hex = hex.padStart(16, '0');
    const bytes = [];
    for (let i = 0; i < 16; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
  }

  // Encode TLV Information Element (Type: 16-bit, Length: 16-bit, Value: bytes)
  function encodeIE(type, valueBytes) {
    const len = valueBytes.length;
    const out = [];
    // Type (2 bytes)
    out.push((type >> 8) & 0xFF, type & 0xFF);
    // Length (2 bytes)
    out.push((len >> 8) & 0xFF, len & 0xFF);
    // Value
    for (let i = 0; i < len; i++) {
      out.push(valueBytes[i]);
    }
    return out;
  }

  // Build F-SEID IE (Type 57)
  function buildFSEID(seidHex, ipStr) {
    const val = [];
    val.push(0x02); // Flags: V4=1, V6=0
    val.push(...seidToBytes(seidHex));
    val.push(...ipToBytes(ipStr));
    return encodeIE(57, val);
  }

  // Build Node ID IE (Type 60)
  function buildNodeID(nodeFqdnOrIp) {
    const val = [];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(nodeFqdnOrIp)) {
      val.push(0x00); // Node ID Type: IPv4
      val.push(...ipToBytes(nodeFqdnOrIp));
    } else {
      val.push(0x02); // Node ID Type: FQDN
      for (let i = 0; i < nodeFqdnOrIp.length; i++) {
        val.push(nodeFqdnOrIp.charCodeAt(i));
      }
    }
    return encodeIE(60, val);
  }

  // Build Create PDR IE (Type 56, Grouped)
  function buildCreatePDR(pdrId, precedence, sourceIntf, teid, dnn, ueIp, farId, qerId, urrId) {
    const pdiGroup = [];
    // Source Interface (Type 20) -> 1=Access, 2=Core
    pdiGroup.push(...encodeIE(20, [sourceIntf & 0xFF]));

    // Local F-TEID (Type 21) -> If uplink from gNodeB
    if (sourceIntf === 1 && teid) {
      const fteidVal = [0x01]; // Flags: V4=1
      fteidVal.push((teid >> 24) & 0xFF, (teid >> 16) & 0xFF, (teid >> 8) & 0xFF, teid & 0xFF);
      fteidVal.push(...ipToBytes('192.168.100.1')); // UPF Ingress IP
      pdiGroup.push(...encodeIE(21, fteidVal));
    }

    // Network Instance (DNN) (Type 22)
    if (dnn) {
      const dnnBytes = [];
      for (let i = 0; i < dnn.length; i++) dnnBytes.push(dnn.charCodeAt(i));
      pdiGroup.push(...encodeIE(22, dnnBytes));
    }

    // UE IP Address (Type 93)
    if (ueIp) {
      const ueIpBytes = [0x02]; // V4=1
      ueIpBytes.push(...ipToBytes(ueIp));
      pdiGroup.push(...encodeIE(93, ueIpBytes));
    }

    // Assemble PDR Grouped IE
    const pdrVal = [];
    // PDR ID (Type 56/IE inside or sub-IE 16-bit ID)
    pdrVal.push(...encodeIE(56, [(pdrId >> 8) & 0xFF, pdrId & 0xFF]));
    // Precedence (Type 29, 32-bit)
    pdrVal.push(...encodeIE(29, [(precedence >> 24) & 0xFF, (precedence >> 16) & 0xFF, (precedence >> 8) & 0xFF, precedence & 0xFF]));
    // PDI (Type 2)
    pdrVal.push(...encodeIE(2, pdiGroup));

    // Outer Header Removal (Type 95) -> 0 = GTP-U/UDP/IPv4
    if (sourceIntf === 1) {
      pdrVal.push(...encodeIE(95, [0x00]));
    }

    // Associated FAR ID (Type 108)
    pdrVal.push(...encodeIE(108, [(farId >> 24) & 0xFF, (farId >> 16) & 0xFF, (farId >> 8) & 0xFF, farId & 0xFF]));
    // Associated QER ID (Type 109)
    pdrVal.push(...encodeIE(109, [(qerId >> 24) & 0xFF, (qerId >> 16) & 0xFF, (qerId >> 8) & 0xFF, qerId & 0xFF]));
    // Associated URR ID (Type 81)
    pdrVal.push(...encodeIE(81, [(urrId >> 24) & 0xFF, (urrId >> 16) & 0xFF, (urrId >> 8) & 0xFF, urrId & 0xFF]));

    return encodeIE(56, pdrVal);
  }

  // Build Create FAR IE (Type 108, Grouped)
  function buildCreateFAR(farId, actionBits, destIntf, remoteTeid, remoteIp) {
    const farVal = [];
    // FAR ID
    farVal.push(...encodeIE(108, [(farId >> 24) & 0xFF, (farId >> 16) & 0xFF, (farId >> 8) & 0xFF, farId & 0xFF]));
    // Apply Action (Type 44): Bit 1=DROP, Bit 2=FORW, Bit 3=BUFF, Bit 4=NOCP
    farVal.push(...encodeIE(44, [actionBits & 0xFF]));

    // Forwarding Parameters (Type 4, Grouped) if FORW is set
    if (actionBits & 0x02) {
      const fwdParams = [];
      fwdParams.push(...encodeIE(42, [destIntf & 0xFF])); // Destination Interface
      if (remoteTeid && remoteIp) {
        // Outer Header Creation (Type 84) -> GTP-U/UDP/IPv4 (0x0100)
        const ohc = [0x01, 0x00];
        ohc.push((remoteTeid >> 24) & 0xFF, (remoteTeid >> 16) & 0xFF, (remoteTeid >> 8) & 0xFF, remoteTeid & 0xFF);
        ohc.push(...ipToBytes(remoteIp));
        fwdParams.push(...encodeIE(84, ohc));
      }
      farVal.push(...encodeIE(4, fwdParams));
    }

    return encodeIE(108, farVal);
  }

  // Build Create QER IE (Type 109, Grouped)
  function buildCreateQER(qerId, qfi, mbrUlKbps, mbrDlKbps) {
    const qerVal = [];
    // QER ID
    qerVal.push(...encodeIE(109, [(qerId >> 24) & 0xFF, (qerId >> 16) & 0xFF, (qerId >> 8) & 0xFF, qerId & 0xFF]));
    // Gate Status (Type 25): UL=OPEN (0), DL=OPEN (0) -> 0x00
    qerVal.push(...encodeIE(25, [0x00]));
    // MBR (Type 72): 40-bit UL + 40-bit DL in kbps
    const mbrBytes = [];
    const ul = BigInt(mbrUlKbps);
    const dl = BigInt(mbrDlKbps);
    for (let i = 4; i >= 0; i--) mbrBytes.push(Number((ul >> BigInt(i * 8)) & 0xFFn));
    for (let i = 4; i >= 0; i--) mbrBytes.push(Number((dl >> BigInt(i * 8)) & 0xFFn));
    qerVal.push(...encodeIE(72, mbrBytes));
    // QFI (Type 124)
    qerVal.push(...encodeIE(124, [qfi & 0x3F]));

    return encodeIE(109, qerVal);
  }

  // Build Create URR IE (Type 81, Grouped)
  function buildCreateURR(urrId, volThresholdMB) {
    const urrVal = [];
    // URR ID
    urrVal.push(...encodeIE(81, [(urrId >> 24) & 0xFF, (urrId >> 16) & 0xFF, (urrId >> 8) & 0xFF, urrId & 0xFF]));
    // Measurement Method (Type 62): Volume (1)
    urrVal.push(...encodeIE(62, [0x01]));
    // Reporting Triggers (Type 37): Volume Threshold (0x02)
    urrVal.push(...encodeIE(37, [0x00, 0x02]));
    // Volume Threshold (Type 31): Total Volume 64-bit
    const totalBytes = BigInt(volThresholdMB) * 1024n * 1024n;
    const volBytes = [0x01]; // Flags: Total volume present
    for (let i = 7; i >= 0; i--) volBytes.push(Number((totalBytes >> BigInt(i * 8)) & 0xFFn));
    urrVal.push(...encodeIE(31, volBytes));

    return encodeIE(81, urrVal);
  }

  // Master PFCP Binary Packet Encoder (3GPP TS 29.244 Header + IEs)
  function encodePFCPMessage(params) {
    const msgType = params.msgType || 50; // Session Establishment Request
    const seqNum = params.seqNum || 1042;
    const hasSeid = params.hasSeid !== undefined ? params.hasSeid : (msgType >= 50);
    const seidHex = params.seidHex || '0x0000000000000001';

    const iePayload = [];

    // Node ID IE
    iePayload.push(...buildNodeID(params.smfNodeId || 'smf01.carrier.5g'));

    // If Session message, include F-SEID
    if (hasSeid) {
      iePayload.push(...buildFSEID(seidHex, params.smfIp || '10.200.1.10'));
    }

    // If Session Establishment (Type 50), include PDR, FAR, QER, URR
    if (msgType === 50) {
      // Uplink PDR: Access interface -> Match gNodeB TEID
      iePayload.push(...buildCreatePDR(
        1, // PDR ID 1
        100, // Precedence 100
        1, // Source Interface: Access
        params.uplinkTeid || 0x12345678,
        params.dnn || 'internet',
        params.ueIp || '10.45.0.2',
        1, // FAR ID 1
        1, // QER ID 1
        1  // URR ID 1
      ));

      // Downlink PDR: Core interface -> Match UE IP
      iePayload.push(...buildCreatePDR(
        2, // PDR ID 2
        100, // Precedence 100
        2, // Source Interface: Core
        0,
        params.dnn || 'internet',
        params.ueIp || '10.45.0.2',
        2, // FAR ID 2
        1, // QER ID 1
        1  // URR ID 1
      ));

      // Uplink FAR: Forward to SGi-LAN / Data Network
      iePayload.push(...buildCreateFAR(1, 0x02, 3, 0, null)); // Action: FORW (0x02), Dest: SGi-LAN (3)

      // Downlink FAR: Forward to gNodeB via GTP-U encapsulation (or Buffer if UE Idle)
      if (params.ueIdle) {
        // Apply Action: BUFF (0x04) + NOCP (0x08) = 0x0C
        iePayload.push(...buildCreateFAR(2, 0x0C, 1, 0, null));
      } else {
        // Apply Action: FORW (0x02), Dest: Access (1), Encapsulate to gNodeB TEID
        iePayload.push(...buildCreateFAR(2, 0x02, 1, params.downlinkTeid || 0x87654321, params.gnbIp || '198.51.100.10'));
      }

      // QER: QFI 9 (Default Internet) or 1 (VoNR), MBR 1Gbps / 100Mbps
      iePayload.push(...buildCreateQER(1, params.qfi || 9, params.mbrUlKbps || 100000, params.mbrDlKbps || 1000000));

      // URR: Volume measurement with 500MB threshold
      iePayload.push(...buildCreateURR(1, params.urrQuotaMB || 500));
    }

    // PFCP Header:
    // Byte 0: Version=1 (3 bits = 001), Spare (2 bits = 00), FO=0, MP=0, S=(hasSeid ? 1 : 0)
    const headerFlags = 0x20 | (hasSeid ? 0x01 : 0x00);
    const headerLen = hasSeid ? 16 : 8;
    const msgLen = (headerLen - 4) + iePayload.length; // Length field covers bytes after Length field

    const packet = [];
    packet.push(headerFlags);
    packet.push(msgType & 0xFF);
    packet.push((msgLen >> 8) & 0xFF, msgLen & 0xFF);

    if (hasSeid) {
      packet.push(...seidToBytes(seidHex));
    }

    // Sequence Number (3 bytes) + Spare (1 byte)
    packet.push((seqNum >> 16) & 0xFF, (seqNum >> 8) & 0xFF, seqNum & 0xFF);
    packet.push(0x00); // Spare byte

    // Append IEs
    for (let i = 0; i < iePayload.length; i++) {
      packet.push(iePayload[i]);
    }

    return new Uint8Array(packet);
  }

  // Format binary packet into Wireshark-style Hex Dump
  function formatHexDump(uint8Arr) {
    const lines = [];
    for (let i = 0; i < uint8Arr.length; i += 16) {
      const offset = i.toString(16).padStart(4, '0');
      const slice = uint8Arr.slice(i, i + 16);
      let hexPart = '';
      let asciiPart = '';

      for (let j = 0; j < 16; j++) {
        if (j < slice.length) {
          hexPart += slice[j].toString(16).padStart(2, '0') + ' ';
          asciiPart += (slice[j] >= 32 && slice[j] <= 126) ? String.fromCharCode(slice[j]) : '.';
        } else {
          hexPart += '   ';
        }
      }
      lines.push(`${offset}   ${hexPart.trimEnd().padEnd(48, ' ')}   |${asciiPart}|`);
    }
    return lines.join('\n');
  }

  // Calculate Downlink Buffering & Session State Memory Sizing
  function calculateBufferingSizing(params) {
    const dlBandwidthMbps = parseFloat(params.dlBandwidthMbps) || 100;
    const bufferTimeoutSec = parseFloat(params.bufferTimeoutSec) || 5;
    const idleUeCount = parseInt(params.idleUeCount, 10) || 5000;
    const activeSessions = parseInt(params.activeSessions, 10) || 50000;

    // Burst concurrency factor (percentage of idle UEs receiving downlink paging traffic simultaneously)
    const concurrencyFactor = parseFloat(params.concurrencyFactor) || 0.05; // 5%

    // Buffer needed per active paging burst: (Throughput in MBytes/sec) * Duration
    const burstPerUeMB = (dlBandwidthMbps / 8) * Math.min(bufferTimeoutSec, 2.0); // max 2s burst stored
    const totalConcurrentPagingUes = Math.round(idleUeCount * concurrencyFactor);
    const totalDlBufferRAM_MB = Math.round(totalConcurrentPagingUes * burstPerUeMB);

    // UPF Session Context RAM (PDR, FAR, QER, URR tables in memory)
    // Avg ~4KB per active session in DPDK/VPP hash tables
    const sessionContextRAM_MB = Math.round((activeSessions * 4) / 1024);

    return {
      burstPerUeMB: burstPerUeMB.toFixed(2),
      concurrentPagingUes: totalConcurrentPagingUes,
      totalDlBufferRAM_MB,
      sessionContextRAM_MB,
      totalUpfMemoryGB: ((totalDlBufferRAM_MB + sessionContextRAM_MB) / 1024).toFixed(2),
      bufferOverheadRisk: totalDlBufferRAM_MB > 4096 ? 'CRITICAL_HIGH' : (totalDlBufferRAM_MB > 2048 ? 'MODERATE' : 'OPTIMAL')
    };
  }

  return {
    MESSAGE_TYPES,
    IE_TYPES,
    encodePFCPMessage,
    formatHexDump,
    calculateBufferingSizing,
    buildFSEID,
    buildCreatePDR,
    buildCreateFAR,
    buildCreateQER,
    buildCreateURR
  };
}));
