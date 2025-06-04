// middleware/authMiddleware.js

const jwt = require('jsonwebtoken');
require('dotenv').config();

// NB: Adjust the environment variable name if different
const JWT_SECRET = process.env.JWT_SECRET;

/**
 * verifyToken: Express middleware that checks for a Bearer‐token JWT in the
 * Authorization header. If valid, attaches req.user = { user_id, email, accountType }.
 * If missing/invalid, returns 401 Unauthorized.
 */
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        // payload should have { user_id, email, accountType } if you signed it that way
        req.user = {
            user_id: payload.user_id,
            email: payload.email,
            accountType: payload.accountType
        };
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

module.exports = {
    verifyToken
};
