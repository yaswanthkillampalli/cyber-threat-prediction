import { useState, useMemo } from 'react';
import { Container, Row, Col, Card, Table, Alert, Button, Form } from 'react-bootstrap';
import { BounceLoader } from 'react-spinners';

// --- ASSUMED CHART IMPORTS ---
// Make sure you have these chart components created and imported from their correct paths.
import ThreatLevelGauge from '../charts/ThreatLevelGauge';
import SimpleLineChart from '../charts/SimpleLineChart';
import SimpleAreaChart from '../charts/SimpleAreaChart';
import SimpleBarChart from '../charts/SimpleBarChart';
import StackedBarChart from '../charts/StackedBarChart';
import BreakdownPieChart from '../charts/BreakdownPieChart';
import SimpleRadarChart from '../charts/SimpleRadarChart';
import ScatterPlot from '../charts/ScatterPlot';

// --- STYLES ---
const overlayStyle = {
  position: 'fixed',
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  backgroundColor: 'rgba(0, 0, 0, 0.7)',
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
  alignItems: 'center',
  zIndex: 9999,
  color: 'white'
};

export default function ApiAnalysis() {
  const [apiUrl, setApiUrl] = useState('');
  const [isUrlSubmitted, setIsUrlSubmitted] = useState(false);
  const [status, setStatus] = useState({ type: 'idle', message: '' }); // idle | uploading | success | error

  // Server-returned data
  const [dashboardData, setDashboardData] = useState(null);
  const [trafficData, setTrafficData] = useState(null);
  const [behaviourData, setBehaviourData] = useState(null);
  const [packetData, setPacketData] = useState(null);

  // Coercers to prevent NaN in charts
  const safeThreatBreakdown = useMemo(
    () => (dashboardData?.threatBreakdown || []).map(d => ({ ...d, value: Number(d.value) || 0 })),
    [dashboardData]
  );
  const safeTopAttackedPorts = useMemo(
    () => (dashboardData?.topAttackedPorts || []).map(d => ({ ...d, count: Number(d.count) || 0 })),
    [dashboardData]
  );
  const safeThreatsOverTime = useMemo(
    () => (dashboardData?.threatsOverTime || []).map(d => ({ ...d, threats: Number(d.threats) || 0 })),
    [dashboardData]
  );
  const safeProtocolBreakdown = useMemo(
    () => (trafficData?.protocolBreakdown || []).map(d => ({ ...d, value: Number(d.value) || 0 })),
    [trafficData]
  );
  const safeTrafficVolume = useMemo(
    () => (trafficData?.trafficVolume || []).map(d => ({ ...d, volume: Number(d.volume) || 0 })),
    [trafficData]
  );
  const safeSentReceived = useMemo(
    () => (trafficData?.sentReceived || []).map(d => ({
      ...d,
      sent: Number(d.sent) || 0,
      received: Number(d.received) || 0
    })),
    [trafficData]
  );
  const safeFlagProfiles = useMemo(
    () => (packetData?.flagProfiles || []).map(d => ({
      ...d,
      benign: Number(d.benign) || 0,
      malicious: Number(d.malicious) || 0
    })),
    [packetData]
  );
  const safeAvgPacketSize = useMemo(
    () => (packetData?.avgPacketSize || []).map(d => ({ ...d, count: Number(d.count) || 0 })),
    [packetData]
  );

  // Scatter data adapters
  const flowDurationData = useMemo(() => ({
    benign: (behaviourData?.flowDuration?.benign || []).map(d => ({
      duration: Number(d.duration) || 0,
      packets: Number(d.packets) || 0,
      size: Number(d.size) || 0
    })),
    malicious: (behaviourData?.flowDuration?.malicious || []).map(d => ({
      duration: Number(d.duration) || 0,
      packets: Number(d.packets) || 0,
      size: Number(d.size) || 0
    }))
  }), [behaviourData]);

  const packetTimingData = useMemo(() => ({
    benign: (behaviourData?.packetTiming?.benign || []).map(d => ({
      iatMean: Number(d.iatMean) || 0,
      iatStd: Number(d.iatStd) || 0
    })),
    malicious: (behaviourData?.packetTiming?.malicious || []).map(d => ({
      iatMean: Number(d.iatMean) || 0,
      iatStd: Number(d.iatStd) || 0
    }))
  }), [behaviourData]);

  const resetAll = () => {
    setApiUrl('');
    setIsUrlSubmitted(false);
    setDashboardData(null);
    setTrafficData(null);
    setBehaviourData(null);
    setPacketData(null);
    setStatus({ type: 'idle', message: '' });
  };

  const handleUrlSubmit = (e) => {
    e.preventDefault();
    if (apiUrl.trim()) {
      setIsUrlSubmitted(true);
      setStatus({ type: 'idle', message: '' });
    } else {
        setStatus({ type: 'error', message: 'Please enter a valid API URL.'})
    }
  };

  const uploadToBackend = async () => {
    if (!apiUrl || !isUrlSubmitted) return;

    try {
      setStatus({ type: 'uploading', message: 'Fetching and analyzing data from API...' });
      
      const res = await fetch('http://localhost:8000/analyze/api', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ apiUrl: apiUrl }),
      });

      if (!res.ok) throw new Error(`Analysis failed with status: ${res.status}`);
      
      const payload = await res.json();
      setDashboardData(payload.dashboardData || null);
      setTrafficData(payload.trafficData || null);
      setBehaviourData(payload.behaviourData || null);
      setPacketData(payload.packetData || null);

      setStatus({ type: 'success', message: 'Analysis complete.' });
    } catch (e) {
      setStatus({ type: 'error', message: e.message || 'An unknown error occurred' });
    }
  };

  return (
    <Container fluid className="py-4">
      {status.type === 'uploading' && (
        <div style={overlayStyle}>
          <BounceLoader color={"#3b82f6"} loading={true} size={80} />
          <p className="mt-4 fs-5">{status.message}</p>
        </div>
      )}

      {!isUrlSubmitted ? (
        <Card>
          <Card.Body>
            <Card.Title>Provide API Link</Card.Title>
            <Card.Text>Enter the full URL to the CSV data source you want to analyze.</Card.Text>
            <Form onSubmit={handleUrlSubmit}>
              <Form.Group controlId="apiUrlInput">
                <Form.Label>API URL</Form.Label>
                <Form.Control
                  type="url"
                  placeholder="https://example.com/data.csv"
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  required
                />
              </Form.Group>
               {status.type === 'error' && (
                <Alert className="mt-3 mb-0" variant="danger">{status.message}</Alert>
              )}
              <Button variant="primary" type="submit" className="mt-3">
                Submit URL
              </Button>
            </Form>
          </Card.Body>
        </Card>
      ) : (
        <>
          <Card className="mb-4">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <Card.Title className="mb-1">API Link Submitted</Card.Title>
                  <p className="mb-0 text-muted" style={{ wordBreak: 'break-all' }}>{apiUrl}</p>
                </div>
                <div className="d-flex gap-2">
                  <Button variant="outline-secondary" size="sm" onClick={resetAll}>
                    Change API Link
                  </Button>
                  <Button
                    variant="primary"
                    onClick={uploadToBackend}
                    disabled={status.type === 'uploading'}
                  >
                    Analyze on Server
                  </Button>
                </div>
              </div>

              {status.type === 'error' && (
                <Alert className="mt-3 mb-0" variant="danger">{status.message}</Alert>
              )}
              {status.type === 'success' && (
                <Alert className="mt-3 mb-0" variant="success">{status.message}</Alert>
              )}
            </Card.Body>
          </Card>

          {status.type === 'success' && dashboardData && (
            <>
              {/* Dashboard */}
              <Row className="mb-4">
                <Col md={4}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Threat Level</Card.Title>
                      <ThreatLevelGauge percentage={Number(dashboardData.threatLevel) || 0} />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={8}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Threats Over Time</Card.Title>
                      <SimpleLineChart data={safeThreatsOverTime} xKey="time" yKey="threats" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Threat Breakdown</Card.Title>
                      <BreakdownPieChart data={safeThreatBreakdown} nameKey="name" valueKey="value" />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Top Attacked Ports</Card.Title>
                      <SimpleBarChart data={safeTopAttackedPorts} dataKey="count" nameKey="name" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              {/* Traffic Analysis */}
              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Traffic Volume</Card.Title>
                      <SimpleAreaChart data={safeTrafficVolume} xKey="time" yKey="volume" />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Protocol Breakdown</Card.Title>
                      <BreakdownPieChart data={safeProtocolBreakdown} nameKey="name" valueKey="value" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              <Row className="mb-4">
                <Col md={12}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Sent vs Received (by class)</Card.Title>
                      <StackedBarChart
                        data={safeSentReceived}
                        xKey="name"
                        stackKeys={['sent', 'received']}
                        legend
                      />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              {/* Behaviour Analysis */}
              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Flow Duration vs Packets</Card.Title>
                      <ScatterPlot
                        data={flowDurationData}
                        xAxis={{ key: 'duration', name: 'Duration', unit: 'µs' }}
                        yAxis={{ key: 'packets', name: 'Packets', unit: '' }}
                        zAxis={{ key: 'size', name: 'Payload Size', unit: 'bytes' }}
                        series={[
                          { key: 'benign', color: '#198754', name: 'Benign' },
                          { key: 'malicious', color: '#dc3545', name: 'Malicious' }
                        ]}
                      />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Packet Timing (IAT)</Card.Title>
                      <ScatterPlot
                        data={packetTimingData}
                        xAxis={{ key: 'iatMean', name: 'Mean IAT', unit: 'time' }}
                        yAxis={{ key: 'iatStd', name: 'Std Dev of IAT', unit: 'time' }}
                        zAxis={{ key: 'iatMean', name: 'Mean IAT', unit: 'time' }}
                        series={[
                          { key: 'benign', color: '#0d6efd', name: 'Benign' },
                          { key: 'malicious', color: '#fd7e14', name: 'Malicious' }
                        ]}
                      />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              {/* Packet Analysis */}
              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>TCP Flag Profiles</Card.Title>
                      <SimpleRadarChart
                        data={safeFlagProfiles}
                        angleKey="flag"
                        radiusKeys={['benign', 'malicious']}
                      />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Average Packet Size by Class</Card.Title>
                      <SimpleBarChart data={safeAvgPacketSize} dataKey="count" nameKey="name" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>
              <Row>
                <Col md={12}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Recent Malicious Flows</Card.Title>
                      <Table striped bordered hover responsive>
                        <thead>
                          <tr>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Predicted Type</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(trafficData?.recentFlows || []).map((r, i) => (
                            <tr key={i}>
                              <td>{r.source}</td>
                              <td>{r.dest}</td>
                              <td>{r.port}</td>
                              <td>{r.protocol}</td>
                              <td><span className={`badge ${r.type === 'benign' ? 'bg-success' : 'bg-danger'}`}>{r.type}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </Table>
                    </Card.Body>
                  </Card>
                </Col>
              </Row>
            </>
          )}
        </>
      )}
    </Container>
  );
}