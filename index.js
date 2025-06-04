// index.js

const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/authRoutes');
const protectedRoutes = require('./routes/protectedRoutes');
const adminRoutes = require('./routes/adminRoutes');

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Mount authentication routes
app.use('/api/auth', authRoutes);

// Mount user‐protected routes
app.use('/api', protectedRoutes);

// Mount admin‐only routes
app.use('/api', adminRoutes);

// Health check
app.get('/', (req, res) => {
    res.send({ message: 'JuanEye Backend API is running.' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err);
    res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
});

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});

module.exports = app;