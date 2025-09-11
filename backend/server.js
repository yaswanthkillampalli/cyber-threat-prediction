// server.js (Final Comprehensive Version)

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const Papa = require('papaparse');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
const { transformPredictionData } = require('./analysis-transformer.js');

// --- CONFIGURATION ---
const PORT = process.env.PORT || 8000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;
const MODEL_API_URL_SINGLE = process.env.MODEL_API_URL_SINGLE;
const MODEL_API_URL_BATCH = process.env.MODEL_API_URL_BATCH;

// --- INITIALIZATION ---
const app = express();
app.use(cors());
app.use(express.json()); // Middleware to parse JSON bodies
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });


// --- API ENDPOINTS ---

// Endpoint 6: Health Check
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date() });
});


// Endpoint 1: Get Analysis for the Last 24 Hours
app.get('/reports/recent', async (req, res) => {
    try {
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const { data, error } = await supabase
            .from('network_flows')
            .select('*')
            .gte('created_at', twentyFourHoursAgo)
            .limit(10000);

        if (error) throw error;
        if (!data || data.length === 0) return res.json({ message: "No data found for the last 24 hours." });
        
        const finalDashboardData = transformPredictionData(data);
        res.json(finalDashboardData);
    } catch (error) {
        res.status(500).json({ error: `Failed to fetch recent report: ${error.message}` });
    }
});


// Endpoint 2: Get Analysis for a Custom Date Range
app.get('/reports/custom', async (req, res) => {
    const { start, end } = req.query; // e.g., ?start=2025-09-01&end=2025-09-05
    if (!start || !end) {
        return res.status(400).json({ error: 'Please provide both a "start" and "end" query parameter.' });
    }
    try {
        const { data, error } = await supabase
            .from('network_flows')
            .select('*')
            .gte('created_at', new Date(start).toISOString())
            .lte('created_at', new Date(end).toISOString())
            .limit(10000);

        if (error) throw error;
        if (!data || data.length === 0) {
            return res.json({ message: "No data found for the specified date range." });
        }
        console.log(data.length);
        const finalDashboardData = transformPredictionData(data);
        res.json(finalDashboardData);
    } catch (error) {
        res.status(500).json({ error: `Failed to fetch custom report: ${error.message}` });
    }
});


// Endpoint 3: Analyze a new CSV file
app.post('/analyze/csv', upload.single('csvfile'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No CSV file provided.' });

    try {
        const csvString = req.file.buffer.toString('utf8');
        const { data: rows } = Papa.parse(csvString, { header: true, skipEmptyLines: true, dynamicTyping: true });

        const BATCH_SIZE = 100;
        const resultsWithPredictions = [];
        for (let i = 0; i < rows.length; i += BATCH_SIZE) {
            const batch = rows.slice(i, i + BATCH_SIZE);
            const batchForModel = batch.map(({ Timestamp, timestamp, ...rest }) => rest);
            try {
                const response = await axios.post(MODEL_API_URL_BATCH, batchForModel);
                const predictions = response.data.predictions;
                const batchWithPredictions = batch.map((row, index) => ({ ...row, prediction: predictions[index] || 'Error' }));
                resultsWithPredictions.push(...batchWithPredictions);
            } catch (error) {
                const errorBatch = batch.map(row => ({ ...row, prediction: 'Error' }));
                resultsWithPredictions.push(...errorBatch);
            }
        }
        
        const finalDashboardData = transformPredictionData(resultsWithPredictions);
        res.json(finalDashboardData);
    } catch (error) {
        res.status(500).json({ error: `Failed to process CSV file: ${error.message}` });
    }
});


// Endpoint 4: Ingest a single data row
app.post('/ingest/single', async (req, res) => {
    const row = req.body;
    if (!row || Object.keys(row).length === 0) {
        return res.status(400).json({ error: 'No data row provided in request body.' });
    }
    try {
        const { timestamp, ...rowForModel } = row;
        const response = await axios.post(MODEL_API_URL_SINGLE, rowForModel);
        const dataToInsert = { ...row, predicted_label: response.data.prediction };

        const { error } = await supabase.from('network_flows').insert(dataToInsert);
        if (error) throw error;

        res.status(201).json({ success: true, message: 'Data ingested and stored successfully.', data: dataToInsert });
    } catch (error) {
        res.status(500).json({ error: `Failed to ingest data: ${error.message}` });
    }
});


// Endpoint 5: Ingest a batch of data rows
app.post('/ingest/batch', async (req, res) => {
    const rows = req.body;
    if (!rows || !Array.isArray(rows) || rows.length === 0) {
        return res.status(400).json({ error: 'Request body must be a non-empty array of data rows.' });
    }
    try {
        const BATCH_SIZE = 100;
        const allDataToInsert = [];
        for (let i = 0; i < rows.length; i += BATCH_SIZE) {
            const batch = rows.slice(i, i + BATCH_SIZE);
            const batchForModel = batch.map(({ timestamp, ...rest }) => rest);
            try {
                const response = await axios.post(MODEL_API_URL_BATCH, batchForModel);
                const predictions = response.data.predictions;
                const batchWithPredictions = batch.map((row, index) => ({ ...row, predicted_label: predictions[index] || 'Error' }));
                allDataToInsert.push(...batchWithPredictions);
            } catch (error) {
                // If prediction fails for a batch, we'll still try to insert with 'Error' label
                const errorBatch = batch.map(row => ({ ...row, predicted_label: 'Error' }));
                allDataToInsert.push(...errorBatch);
            }
        }

        const { error } = await supabase.from('network_flows').insert(allDataToInsert);
        if (error) throw error;
        
        res.status(201).json({ success: true, message: `Successfully ingested and stored ${allDataToInsert.length} records.` });
    } catch (error) {
        res.status(500).json({ error: `Failed to ingest batch data: ${error.message}` });
    }
});



app.get('/reports/date-range', async (req, res) => {
    try {
        const { data, error } = await supabase.rpc('get_date_range');
        if (error) throw error;
        res.json(data[0]);
    } catch (error) {
        res.status(500).json({ error: `Failed to fetch date range: ${error.message}` });
    }
});

// --- START THE SERVER ---
app.listen(PORT, () => {
    console.log(`✅ Node.js backend listening on port ${PORT}`);
});