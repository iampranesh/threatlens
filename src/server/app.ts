import express from 'express';
import { apiRouter } from './apiRouter.ts';

export const app = express();

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Mount API routes
app.use('/api', apiRouter);

export default app;
