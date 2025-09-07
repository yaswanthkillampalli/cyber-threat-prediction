// src/components/CSVAnalysis.jsx

import { useState, useCallback, useMemo } from 'react';
import { useDropzone } from 'react-dropzone';
import Papa from 'papaparse';
import { Container, Row, Col, Card, Form, Table, Spinner, Alert } from 'react-bootstrap';
import BreakdownPieChart from '../charts/BreakdownPieChart';
import SimpleBarChart from '../charts/SimpleBarChart';

// Styles for the drag-and-drop area
const baseStyle = {
  flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center',
  padding: '40px', border: '2px dashed #007bff', borderRadius: '0.375rem',
  backgroundColor: '#f8f9fa', color: '#6c757d', transition: 'border .24s ease-in-out'
};
const activeStyle = { borderColor: '#0b5ed7' };

export default function CSVAnalysis() {
  const [file, setFile] = useState(null);
  const [data, setData] = useState([]);
  const [headers, setHeaders] = useState([]);
  const [status, setStatus] = useState({ type: 'idle', message: '' }); // idle, parsing, success, error

  // State for interactive analysis
  const [selectedColumn, setSelectedColumn] = useState('');

  const onDrop = useCallback((acceptedFiles) => {
    if (acceptedFiles.length > 0) {
      const uploadedFile = acceptedFiles[0];
      if (uploadedFile.type !== 'text/csv') {
        setStatus({ type: 'error', message: 'Invalid file type. Please upload a CSV file.' });
        return;
      }
      setFile(uploadedFile);
      setStatus({ type: 'parsing', message: 'Parsing CSV file...' });

      // Use PapaParse to process the file
      Papa.parse(uploadedFile, {
        header: true,
        skipEmptyLines: true,
        complete: (results) => {
          setData(results.data);
          setHeaders(results.meta.fields);
          setSelectedColumn(results.meta.fields[0]); // Select the first column by default
          setStatus({ type: 'success', message: `Successfully parsed ${results.data.length} rows.` });
        },
        error: (error) => {
          setStatus({ type: 'error', message: `Error parsing file: ${error.message}` });
        },
      });
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop });
  
  // Memoize chart data to avoid recalculating on every render
  const chartData = useMemo(() => {
    if (!selectedColumn || data.length === 0) return [];
    
    const counts = data.reduce((acc, row) => {
      const value = row[selectedColumn];
      acc[value] = (acc[value] || 0) + 1;
      return acc;
    }, {});
    
    return Object.entries(counts)
      .map(([name, count]) => ({ name: String(name), value: count, count })) // for both pie and bar charts
      .sort((a, b) => b.count - a.count)
      .slice(0, 10); // Limit to top 10 for clarity
  }, [data, selectedColumn]);

  return (
    <Container fluid>
      {!file ? (
        <div {...getRootProps({ style: isDragActive ? { ...baseStyle, ...activeStyle } : baseStyle })}>
          <input {...getInputProps()} />
          <p>Drag 'n' drop a CSV file here, or click to select a file</p>
        </div>
      ) : (
        <>
          <Card className="mb-4">
            <Card.Body>
              <Card.Title>File Summary</Card.Title>
              {status.type === 'parsing' && <Spinner animation="border" />}
              {status.type === 'error' && <Alert variant="danger">{status.message}</Alert>}
              {status.type === 'success' && (
                <Row>
                  <Col><strong>File Name:</strong> {file.name}</Col>
                  <Col><strong>Total Rows:</strong> {data.length}</Col>
                  <Col><strong>Total Columns:</strong> {headers.length}</Col>
                </Row>
              )}
            </Card.Body>
          </Card>

          {status.type === 'success' && (
            <>
              <Row className="mb-4">
                <Col md={12}>
                  <Card>
                    <Card.Body>
                      <Form.Group>
                        <Form.Label><strong>Analyze a Column</strong></Form.Label>
                        <Form.Select value={selectedColumn} onChange={e => setSelectedColumn(e.target.value)}>
                          {headers.map(h => <option key={h} value={h}>{h}</option>)}
                        </Form.Select>
                      </Form.Group>
                    </Card.Body>
                  </Card>
                </Col>
              </Row>
              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Top 10 Value Counts (Bar Chart)</Card.Title>
                      <SimpleBarChart data={chartData} />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Value Distribution (Pie Chart)</Card.Title>
                      <BreakdownPieChart data={chartData} />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>
              <Row>
                <Col>
                  <Card>
                    <Card.Body>
                      <Card.Title>Data Preview (First 100 Rows)</Card.Title>
                      <Table striped bordered hover responsive>
                        <thead>
                          <tr>{headers.map(h => <th key={h}>{h}</th>)}</tr>
                        </thead>
                        <tbody>
                          {data.slice(0, 100).map((row, i) => (
                            <tr key={i}>{headers.map(h => <td key={h}>{row[h]}</td>)}</tr>
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