// src/charts/SimpleBarChart.jsx

import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from 'recharts';

export default function SimpleBarChart({ data = [] }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} layout="vertical" margin={{ left: 20 }}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis type="number" />
        <YAxis dataKey="name" type="category" width={100} />
        <Tooltip wrapperStyle={{ backgroundColor: '#333', border: 'none' }} />
        <Legend />
        <Bar dataKey="count" fill="#3b82f6" name="Attack Count" />
      </BarChart>
    </ResponsiveContainer>
  );
}