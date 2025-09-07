// src/charts/StackedBarChart.jsx

import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from 'recharts';

export default function StackedBarChart({ data = [] }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="name" />
        <YAxis label={{ value: 'Gigabytes (GB)', angle: -90, position: 'insideLeft' }} />
        <Tooltip wrapperStyle={{ backgroundColor: '#333', border: 'none' }} />
        <Legend />
        <Bar dataKey="sent" stackId="a" fill="#3b82f6" name="Data Sent" />
        <Bar dataKey="received" stackId="a" fill="#8b5cf6" name="Data Received" />
      </BarChart>
    </ResponsiveContainer>
  );
}