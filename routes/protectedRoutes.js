// routes/protectedRoutes.js

const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/authMiddleware');
const pool = require('../db');

/**
 * GET /api/dashboard
 * - Requires a valid JWT (any accountType: User, Guardian, or Admin).
 * - Returns a simple dashboard message and the user’s own info.
 */
router.get('/dashboard', verifyToken, async (req, res, next) => {
  try {
    // req.user contains { user_id, email, accountType }
    const { user_id, email, accountType } = req.user;

    // As an example, we can return the user’s own scanCount and premium status:
    const [rows] = await pool.execute(
        `SELECT scanCount, isPremiumUser
       FROM USERS
       WHERE user_id = ?`,
        [user_id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { scanCount, isPremiumUser } = rows[0];

    return res.json({
      message: `Welcome to your dashboard, ${email}!`,
      user: {
        user_id,
        email,
        accountType,
        scanCount,
        isPremiumUser: isPremiumUser === 1
      }
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
