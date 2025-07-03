const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/authMiddleware');
const userController = require('../controllers/userController');

// ─── Protect ALL /api/user/* with JWT ─────────────────────────────────────
router.use(verifyToken);

// GET  /api/user/dashboard
router.get('/user/dashboard', userController.getDashboard);

// GET  /api/user/profile
router.get('/user/profile', userController.getProfile);

// POST /api/user/ocr-scans
router.post('/user/ocr-scans', userController.createOCRScan);

// POST /api/user/object-scans
router.post('/user/object-scans', userController.createObjectScan);

// GET  /api/user/scans
router.get('/user/scans', userController.getUserScans);

// GET  /api/user/scans/user?user_id=<id>
router.get('/user/scans/user', userController.getScansByUser);

// GET  /api/user/scans/:scanId
router.get('/user/scans/:scanId', userController.getSingleScan);

// PUT  /api/user/scans/:scanId
router.put('/user/scans/:scanId', userController.updateScan);

// DELETE /api/user/scans/:scanId
router.delete('/user/scans/:scanId', userController.deleteScan);

// ─── Guardian binding routes ──────────────────────────────────────────────

// POST /api/user/guardian/bind-request
router.post('/user/guardian/bind-request', userController.requestGuardianBind);

// POST /api/user/guardian/bind-confirm
router.post('/user/guardian/bind-confirm', userController.confirmGuardianBind);

// GET  /api/user/guardian/bound-users
router.get('/user/guardian/bound-users', userController.getBoundUsers);

module.exports = router;