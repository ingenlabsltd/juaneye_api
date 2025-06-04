// index.js

const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const bodyParser = require('body-parser');

const authRoutes = require('./routes/authRoutes');
const protectedRoutes = require('./routes/protectedRoutes'); // if needed
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 1) Public authentication (no JWT needed)
app.use('/api/auth', authRoutes);

// 2) User routes (all /api/user/* require a valid JWT)
app.use('/api', userRoutes);

// 3) Any other protectedRoutes (e.g. /api/dashboard if separate; you can keep these here)
//    (If you have /api/dashboard /api/profile in protectedRoutes.js, you can also do:
//     app.use('/api', protectedRoutes); )

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server started on port ${PORT}`);
});

module.exports = app;
