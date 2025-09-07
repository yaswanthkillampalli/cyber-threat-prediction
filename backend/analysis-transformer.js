// analysis-transformer.js (Final Corrected Version)

const COMMON_PORTS = {
  80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 22: 'SSH',
  25: 'SMTP', 53: 'DNS', 3389: 'RDP',
};

function transformPredictionData(rows) {
  if (!rows || rows.length === 0) {
    return { dashboardData: {}, trafficData: {}, behaviourData: {}, packetData: {}, rawData: [] };
  }

  const getKey = (row, key_snake, key_pascal) => row[key_snake] ?? row[key_pascal];

  // --- 1. Filter and Categorize All Rows ---
  const maliciousRows = rows.filter(r => r.predicted_label && r.predicted_label.toLowerCase() !== 'benign' && r.predicted_label !== 'Error');
  const benignRows = rows.filter(r => r.predicted_label && r.predicted_label.toLowerCase() === 'benign');

  // --- 2. Calculate Dashboard Data ---
  const threatLevel = Math.round((maliciousRows.length / rows.length) * 100);

  const threatBreakdown = maliciousRows.reduce((acc, row) => {
    const prediction = row.predicted_label || 'Unknown Attack';
    acc[prediction] = (acc[prediction] || 0) + 1;
    return acc;
  }, {});

  const topAttackedPorts = maliciousRows.reduce((acc, row) => {
    const port = getKey(row, 'dst_port', 'Dst Port');
    if (port) acc[port] = (acc[port] || 0) + 1;
    return acc;
  }, {});
  
  // --- 3. Calculate Traffic Data ---
  const protocolBreakdown = rows.reduce((acc, row) => {
    const protoNum = getKey(row, 'protocol', 'Protocol');
    const proto = protoNum === 6 ? 'TCP' : (protoNum === 17 ? 'UDP' : 'Other');
    acc[proto] = (acc[proto] || 0) + 1;
    return acc;
  }, {});

  // --- 4. Calculate Behaviour Data ---
  const sampleSize = 50;
  const behaviourData = {
    flowDuration: {
      benign: benignRows.slice(0, sampleSize).map(r => ({ duration: getKey(r, 'flow_duration', 'Flow Duration'), packets: (getKey(r, 'tot_fwd_pkts', 'Tot Fwd Pkts') || 0) + (getKey(r, 'tot_bwd_pkts', 'Tot Bwd Pkts') || 0) })),
      malicious: maliciousRows.slice(0, sampleSize).map(r => ({ duration: getKey(r, 'flow_duration', 'Flow Duration'), packets: (getKey(r, 'tot_fwd_pkts', 'Tot Fwd Pkts') || 0) + (getKey(r, 'tot_bwd_pkts', 'Tot Bwd Pkts') || 0) })),
    },
    packetTiming: {
      benign: benignRows.slice(0, sampleSize).map(r => ({ iatMean: getKey(r, 'flow_iat_mean', 'Flow IAT Mean'), iatStd: getKey(r, 'flow_iat_std', 'Flow IAT Std') })),
      malicious: maliciousRows.slice(0, sampleSize).map(r => ({ iatMean: getKey(r, 'flow_iat_mean', 'Flow IAT Mean'), iatStd: getKey(r, 'flow_iat_std', 'Flow IAT Std') })),
    }
  };

  // --- 5. CORRECTED: Calculate ALL Packet Data ---
  const flagProfiles = { SYN: {benign: 0, malicious: 0}, ACK: {benign: 0, malicious: 0}, FIN: {benign: 0, malicious: 0}, RST: {benign: 0, malicious: 0}, PSH: {benign: 0, malicious: 0}, URG: {benign: 0, malicious: 0} };
  
  benignRows.forEach(r => {
    flagProfiles.SYN.benign += getKey(r, 'syn_flag_cnt', 'SYN Flag Cnt') || 0;
    flagProfiles.ACK.benign += getKey(r, 'ack_flag_cnt', 'ACK Flag Cnt') || 0;
    flagProfiles.FIN.benign += getKey(r, 'fin_flag_cnt', 'FIN Flag Cnt') || 0;
    flagProfiles.RST.benign += getKey(r, 'rst_flag_cnt', 'RST Flag Cnt') || 0;
    flagProfiles.PSH.benign += getKey(r, 'psh_flag_cnt', 'PSH Flag Cnt') || 0;
    flagProfiles.URG.benign += getKey(r, 'urg_flag_cnt', 'URG Flag Cnt') || 0;
  });

  maliciousRows.forEach(r => {
    flagProfiles.SYN.malicious += getKey(r, 'syn_flag_cnt', 'SYN Flag Cnt') || 0;
    flagProfiles.ACK.malicious += getKey(r, 'ack_flag_cnt', 'ACK Flag Cnt') || 0;
    flagProfiles.FIN.malicious += getKey(r, 'fin_flag_cnt', 'FIN Flag Cnt') || 0;
    flagProfiles.RST.malicious += getKey(r, 'rst_flag_cnt', 'RST Flag Cnt') || 0;
    flagProfiles.PSH.malicious += getKey(r, 'psh_flag_cnt', 'PSH Flag Cnt') || 0;
    flagProfiles.URG.malicious += getKey(r, 'urg_flag_cnt', 'URG Flag Cnt') || 0;
  });

  // --- 6. Assemble the Final Object ---
  return {
    dashboardData: {
      threatLevel,
      threatBreakdown: Object.entries(threatBreakdown).map(([name, value]) => ({ name, value })),
      topAttackedPorts: Object.entries(topAttackedPorts).sort(([, a], [, b]) => b - a).slice(0, 5).map(([port, count]) => ({ name: `Port ${port} (${COMMON_PORTS[port] || 'Unknown'})`, count })),
      threatsOverTime: [{ time: new Date().toLocaleTimeString(), threats: maliciousRows.length }],
    },
    trafficData: {
      protocolBreakdown: Object.entries(protocolBreakdown).map(([name, value]) => ({ name, value })),
      recentFlows: maliciousRows.slice(0, 5).map(r => ({
        source: getKey(r, 'src_ip', 'Src IP') || 'N/A', dest: getKey(r, 'dst_ip', 'Dst IP') || 'N/A',
        port: getKey(r, 'dst_port', 'Dst Port'), protocol: getKey(r, 'protocol', 'Protocol') === 6 ? 'TCP' : 'UDP',
        type: r.predicted_label
      }))
    },
    behaviourData,
    packetData: {
      flagProfiles: Object.entries(flagProfiles).map(([flag, values]) => ({ flag, ...values })),
    },
    rawData: rows,
  };
}

module.exports = { transformPredictionData };