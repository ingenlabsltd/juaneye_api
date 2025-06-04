// routes/adminRoutes.js

const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/authMiddleware');
const adminController = require('../controllers/adminController');

// Protect everything below with JWT + Admin‐only check
router.use(verifyToken, (req, res, next) => {
    if (req.user.accountType !== 'Admin') {
        return res.status(403).json({ error: 'Forbidden: Admins only' });
    }
    next();
});

// ────────── CREATE USER ───────────────────────────────────────────────────────
router.post('/admin/users', adminController.createUser);
// ──────────────────────────────────────────────────────────────────────────────

// LIST USERS (paginated)
router.get('/admin/users', adminController.listUsers);

// GET ONE USER BY ID
router.get('/admin/users/:userId', adminController.getUserById);

// UPDATE A USER
router.put('/admin/users/:userId', adminController.updateUser);

// DELETE A USER
router.delete('/admin/users/:userId', adminController.deleteUser);

// GET SCANS FOR A USER
router.get('/admin/users/:userId/scans', adminController.getUserScans);

// UPDATE A SCAN (OBJECT or OCR)
router.put('/admin/scans/:scanId', adminController.updateScan);

// DELETE A SCAN (OBJECT or OCR)
router.delete('/admin/scans/:scanId', adminController.deleteScan);

// ADMIN DASHBOARD METRICS
router.get('/admin/dashboard', adminController.getDashboardStats);

// GENERATE A SIGNUPS REPORT FOR A GIVEN DATE
router.get('/admin/report', adminController.generateReport);

module.exports = router;
