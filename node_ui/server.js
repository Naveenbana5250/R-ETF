const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const PORT = process.env.PORT || 4000;

app.use(express.static(path.join(__dirname, '.'), { maxAge: '1d' }));
app.use(express.json({ limit: '10mb' }));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/alert', (req, res) => {
  const alert = req.body;
  if (!alert || !alert.rule) {
    return res.status(400).json({ error: 'Invalid alert' });
  }

  const enrichedAlert = {
    id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
    ts: alert.ts || Date.now(),
    ...alert,
  };

  console.log(`[ALERT] ${enrichedAlert.severity}: ${enrichedAlert.rule}`);
  io.emit('new_alert', enrichedAlert);
  res.status(200).json({ status: 'received', id: enrichedAlert.id });
});

io.on('connection', (socket) => {
  console.log('UI client connected');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`R-ETF UI Server running on http://0.0.0.0:${PORT}`);
});
