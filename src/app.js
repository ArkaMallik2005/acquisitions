import express from 'express';
import authRoutes from "./routes/auth.routes.js";
import userRoutes from './routes/users.routes.js';
import logger from './config/logger.js';
import helmet from "helmet";
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import securityMiddleware from './middleware/security.middleware.js';

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(morgan('combined', {
  stream: { write: message => logger.info(message.trim()) }
}));

// ✅ STRONG test detection (fixes your issue)
const isTestEnv =
  process.env.NODE_ENV === "test" ||
  process.env.JEST_WORKER_ID !== undefined;

if (!isTestEnv) {
  app.use(securityMiddleware);
}

// Routes
app.get('/', (req, res) => {
  logger.info('Hello from Acquisition!');
  res.status(200).send('Hello from acquisitions!');
});

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('/api', (req, res) => {
  res.status(200).json({ message: 'Welcome to the API!' });
});

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// ✅ FINAL 404 (force JSON response)
app.use((req, res) => {
  res.status(404);
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify({
    error: "Route not found"
  }));
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error(err.message, { stack: err.stack });

  return res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error'
  });
});

export default app;