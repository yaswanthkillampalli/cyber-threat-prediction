// src/components/CSVAnalysis.jsx
import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Container, Row, Col, Card, Form, Table, Spinner, Alert, Button } from 'react-bootstrap';
import BreakdownPieChart from '../charts/BreakdownPieChart';
import SimpleBarChart from '../charts/SimpleBarChart';

const baseStyle = {
  flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center',
  padding: '40px', border: '2px dashed #007bff', borderRadius: '0.375rem',
  backgroundColor: '#f8f9fa', color: '#6c757d', transition: 'border .24s ease-in-out'
};

const activeStyle = { borderColor: '#0b5ed7' };

export default function CSVAnalysis() {
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState({ type: 'idle', message: '' }); // idle | uploading | success | error
  // Server-returned data
  const [dashboardData, setDashboardData] = useState(null);
  const [trafficData, setTrafficData] = useState(null);
  const [behaviourData, setBehaviourData] = useState(null);
  const [packetData, setPacketData] = useState(null);

  const [selectedColumn, setSelectedColumn] = useState(''); // optional: backend-assisted column analysis

  const onDrop = useCallback((acceptedFiles) => {
    if (!acceptedFiles?.length) return;
    const uploadedFile = acceptedFiles;
    if (uploadedFile.type !== 'text/csv' && !uploadedFile.name.endsWith('.csv')) {
      setStatus({ type: 'error', message: 'Invalid file type. Please upload a CSV file.' });
      return;
    }
    setFile(uploadedFile);
    setStatus({ type: 'idle', message: '' });
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop, multiple: false, accept: { 'text/csv': ['.csv'] } });

  const uploadToBackend = async () => {
    if (!file) return;
    try {
      setStatus({ type: 'uploading', message: 'Uploading CSV for analysis...' });
      const formData = new FormData();
      formData.append('file', file);
      // Assumes Vite proxy: /api → http://localhost:5000
      const res = await fetch('/api/analyze-csv', {
        method: 'POST',
        body: formData,
      });
      if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
      const payload = await res.json();
      // Expecting backend shape returned by transformPredictionData
      setDashboardData(payload.dashboardData);
      setTrafficData(payload.trafficData);
      setBehaviourData(payload.behaviourData);
      setPacketData(payload.packetData);
      setSelectedColumn(''); // optional reset
      setStatus({ type: 'success', message: 'Analysis complete.' });
    } catch (e) {
      setStatus({ type: 'error', message: e.message || 'Upload failed' });
    }
  };

  return (
    <Container fluid>
      {!file ? (
        <div {...getRootProps({ style: isDragActive ? { ...baseStyle, ...activeStyle } : baseStyle })}>
          <input {...getInputProps()} />
          <p>Drag 'n' drop a CSV file here, or click to select a file</p>
        </div>
      ) : (
        <>
          <Card className="mb-3">
            <Card.Body>
              <Card.Title>File</Card.Title>
              <Row>
                <Col><strong>Name:</strong> {file.name}</Col>
                <Col xs="auto">
                  <Button variant="secondary" onClick={() => { setFile(null); setDashboardData(null); setTrafficData(null); setBehaviourData(null); setPacketData(null); setStatus({ type: 'idle', message: '' }); }}>
                    Choose another
                  </Button>
                </Col>
                <Col xs="auto">
                  <Button variant="primary" onClick={uploadToBackend} disabled={status.type === 'uploading'}>
                    {status.type === 'uploading' ? 'Uploading...' : 'Analyze on server'}
                  </Button>
                </Col>
              </Row>
              {status.type === 'uploading' && <Spinner animation="border" className="mt-3" />}
              {status.type === 'error' && <Alert className="mt-3" variant="danger">{status.message}</Alert>}
              {status.type === 'success' && <Alert className="mt-3" variant="success">{status.message}</Alert>}
            </Card.Body>
          </Card>

          {status.type === 'success' && dashboardData && (
            <>
              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Threat Breakdown</Card.Title>
                      <BreakdownPieChart data={dashboardData.threatBreakdown} />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Top Attacked Ports</Card.Title>
                      <SimpleBarChart data={dashboardData.topAttackedPorts} dataKey="count" nameKey="name" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              {/* Example: more reuse of existing charts */}
              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Protocol Breakdown</Card.Title>
                      <BreakdownPieChart data={trafficData?.protocolBreakdown || []} />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Avg Packet Size</Card.Title>
                      <SimpleBarChart data={packetData?.avgPacketSize || []} dataKey="count" nameKey="name" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              {/* Optional: preview recent flows as a table */}
              {trafficData?.recentFlows?.length ? (
                <Row>
                  <Col>
                    <Card>
                      <Card.Body>
                        <Card.Title>Recent Malicious Flows</Card.Title>
                        <Table striped bordered hover responsive>
                          <thead>
                            <tr>
                              <th>Source</th>
                              <th>Destination</th>
                              <th>Port</th>
                              <th>Protocol</th>
                              <th>Type</th>
                            </tr>
                          </thead>
                          <tbody>
                            {trafficData.recentFlows.map((r, i) => (
                              <tr key={i}>
                                <td>{r.source}</td>
                                <td>{r.dest}</td>
                                <td>{r.port}</td>
                                <td>{r.protocol}</td>
                                <td>{r.type}</td>
                              </tr>
                            ))}
                          </tbody>
                        </Table>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
              ) : null}
            </>
          )}
        </>
      )}
    </Container>
  );
}
