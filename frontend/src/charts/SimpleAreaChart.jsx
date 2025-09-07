// src/charts/SimpleAreaChart.jsx

import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

export default function SimpleAreaChart({ data = [] }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="time" />
        <YAxis label={{ value: 'Megabytes (MB)', angle: -90, position: 'insideLeft' }} />
        <Tooltip wrapperStyle={{ backgroundColor: '#333', border: 'none' }} />
        <Area type="monotone" dataKey="volume" stroke="#16a34a" fill="#4ade80" name="Traffic Volume" />
      </AreaChart>
    </ResponsiveContainer>
  );
}