// analysis-transformer.js (Updated Version)

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
  const maliciousRows = rows.filter(r => r.label && r.label.toLowerCase() !== 'benign' && r.label !== 'Error');
  const benignRows = rows.filter(r => r.label && r.label.toLowerCase() === 'benign');

  // --- 2. Calculate Dashboard Data ---
  const threatLevel = Math.round((maliciousRows.length / rows.length) * 100);

  const threatBreakdown = maliciousRows.reduce((acc, row) => {
    const prediction = row.label || 'Unknown Attack';
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

  // --- 🌟 NEW CALCULATION: Traffic Volume for Area Chart ---
  const totalBytes = rows.reduce((sum, r) => {
    // These keys represent the total bytes sent in forward and backward directions
    const fwdBytes = getKey(r, 'totlen_fwd_pkts', 'Total Length of Fwd Packets') || 0;
    const bwdBytes = getKey(r, 'totlen_bwd_pkts', 'Total Length of Bwd Packets') || 0;
    return sum + fwdBytes + bwdBytes;
  }, 0);
  const totalMegabytes = totalBytes / (1024 * 1024); // Convert bytes to MB

  const trafficVolumeOverTime = [{ 
    time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }), 
    volume: parseFloat(totalMegabytes.toFixed(2)) 
  }];

  // --- 🌟 NEW CALCULATION: Packet Size Breakdown for Pie Chart ---
  const packetSizeBreakdown = rows.reduce((acc, row) => {
      const avgSize = getKey(row, 'pkt_len_mean', 'Packet Length Mean') || 0;
      if (avgSize === 0) return acc; // Skip flows with no packets
      if (avgSize < 150) acc['Small'] = (acc['Small'] || 0) + 1;
      else if (avgSize <= 1000) acc['Medium'] = (acc['Medium'] || 0) + 1;
      else acc['Large'] = (acc['Large'] || 0) + 1;
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

  // --- 5. Calculate Packet Flag Data ---
  const flagProfiles = { SYN: {benign: 0, malicious: 0}, ACK: {benign: 0, malicious: 0}, FIN: {benign: 0, malicious: 0}, RST: {benign: 0, malicious: 0}, PSH: {benign: 0, malicious: 0}, URG: {benign: 0, malicious: 0} };
  
  benignRows.forEach(r => {
    flagProfiles.SYN.benign += getKey(r, 'syn_flag_cnt', 'SYN Flag Cnt') || 0;
    flagProfiles.ACK.benign += getKey(r, 'ack_flag_cnt', 'ACK Flag Cnt') || 0;
    // ... (rest of the flags)
  });

  maliciousRows.forEach(r => {
    flagProfiles.SYN.malicious += getKey(r, 'syn_flag_cnt', 'SYN Flag Cnt') || 0;
    flagProfiles.ACK.malicious += getKey(r, 'ack_flag_cnt', 'ACK Flag Cnt') || 0;
    // ... (rest of the flags)
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
      trafficVolumeOverTime, // For the Area Chart
      recentFlows: maliciousRows.slice(0, 5).map(r => ({
        source: getKey(r, 'src_ip', 'Src IP') || 'N/A', dest: getKey(r, 'dst_ip', 'Dst IP') || 'N/A',
        port: getKey(r, 'dst_port', 'Dst Port'), protocol: getKey(r, 'protocol', 'Protocol') === 6 ? 'TCP' : 'UDP',
        type: r.label
      }))
    },
    behaviourData,
    packetData: {
      flagProfiles: Object.entries(flagProfiles).map(([flag, values]) => ({ flag, ...values })),
      packetSizeBreakdown: Object.entries(packetSizeBreakdown).map(([name, value]) => ({ name: `${name} Packets`, value })), // For a new Pie Chart
    },
    rawData: rows,
  };
}

module.exports = { transformPredictionData };