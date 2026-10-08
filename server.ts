import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { app as apiApp } from './src/server/app.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const server = express();

// Mount API app
server.use(apiApp);

// Serve static frontend build
const distPath = path.resolve(__dirname, 'dist');
server.use(express.static(distPath));

server.get('*', (_req, res) => {
  res.sendFile(path.resolve(distPath, 'index.html'));
});

server.listen(PORT, () => {
  console.log(`[ThreatLens] Production server listening on http://0.0.0.0:${PORT}`);
});
