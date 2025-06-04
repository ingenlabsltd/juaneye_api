// middleware/authMiddleware.js

const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

/**
 * Express middleware that:
 * 1. Reads the Authorization header ("Bearer <token>")
 * 2. Verifies the token using JWT_SECRET
 * 3. If valid, attaches decoded payload to req.user
 * 4. Otherwise, responds with 401 Unauthorized
 */
function verifyToken(req, res, next) {
    // 1. Get the "Authorization" header
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    if (!authHeader) {
        return res.status(401).json({ error: 'Missing Authorization header' });
    }

    // 2. Expect format: "Bearer <token>"
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        return res.status(401).json({ error: 'Malformed Authorization header. Use "Bearer <token>"' });
    }

    const token = parts[1];

    // 3. Verify JWT
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }

        // 4. Attach decoded payload to req.user
        req.user = decoded;
        next();
    });
}

module.exports = { verifyToken };