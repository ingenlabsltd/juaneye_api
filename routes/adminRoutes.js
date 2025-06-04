// routes/adminRoutes.js

const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/authMiddleware');
const adminController = require('../controllers/adminController');

// ─── Protect all routes below with JWT and Admin-only check ─────────────────
router.use(verifyToken, (req, res, next) => {
    // After verifyToken, req.user contains { user_id, email, accountType, ... }
    if (req.user.accountType !== 'Admin') {
        return res.status(403).json({ error: 'Forbidden: Admins only' });
    }
    next();
});
// ──────────────────────────────────────────────────────────────────────────────

// GET /api/admin/dashboard
//   → returns high‐level counts and “new signups last 7 days” data
router.get('/admin/dashboard', adminController.getDashboardStats);

// GET /api/admin/users
//   → query params: page (default=1), limit (default=10), search (optional, email‐substring filter)
router.get('/admin/users', adminController.listUsers);

// GET /api/admin/users/:userId
//   → returns a single user’s detail (for “View”)
router.get('/admin/users/:userId', adminController.getUserById);

// PUT /api/admin/users/:userId
//   → body: { email, accountType, isPremiumUser, scanCount }
//   → updates those fields on USERS
router.put('/admin/users/:userId', adminController.updateUser);

// DELETE /api/admin/users/:userId
//   → deletes a user (and cascades deletes in related tables)
router.delete('/admin/users/:userId', adminController.deleteUser);

// GET /api/admin/users/:userId/scans
//   → returns both Object‐type scans and Text‐type scans for that user, sorted by createdAt DESC
router.get('/admin/users/:userId/scans', adminController.getUserScans);

// PUT /api/admin/scans/:scanId
//   → body: { type, name, text }
//   → if type='Object', updates OBJECT_SCANS; if 'Text', updates OCR_SCANS
router.put('/admin/scans/:scanId', adminController.updateScan);

// DELETE /api/admin/scans/:scanId
//   → deletes the scan (either from OBJECT_SCANS or OCR_SCANS)
router.delete('/admin/scans/:scanId', adminController.deleteScan);

// GET /api/admin/report?date=YYYY-MM-DD
//   → returns all users who signed up on that date (with the same fields as listUsers)
router.get('/admin/report', adminController.generateReport);

module.exports = router;
