// index.js

const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const bodyParser = require('body-parser');

const { auditLog } = require('./middleware/auditMiddleware');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');
const xss        = require('xss-clean');

dotenv.config();

const app = express();
app.use(xss());
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '20mb', extended: true }));

app.use(auditLog);

app.use((req, res, next) => {
    const now = new Date().toISOString();
    let userPart = "";

    if (req.user) {
        userPart = ` user=${req.user.id || req.user.email}`;
    }

    console.log(`[${now} :: ] ${req.method} ${req.originalUrl}${userPart}`);
    next();
});


app.use(bodyParser.json());

// 1) Public authentication (no JWT needed)
app.use('/api/auth', authRoutes);

// 2) User routes (all /api/user/* require a valid JWT)
app.use('/api', userRoutes);


// 4) Admin‐only endpoints (must come AFTER user routes, so /api/admin/* is distinct)
app.use('/api', adminRoutes);

// Health check
app.get('/', (req, res) => {
    res.send({ message: 'JuanEye Backend API is running.' });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error(err);
    res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server started on port ${PORT}`);
});

module.exports = app;
