import express from 'express';

const app = express();

app.get('/', (req, res) => {
    res.status(200).json({ message: 'Hello from acquisitions!' });
});

export default app;