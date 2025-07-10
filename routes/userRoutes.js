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

// GET  /api/user/scans/:scanId
router.get('/user/scans/:scanId', userController.getSingleScan);

// PUT  /api/user/scans/:scanId
router.put('/user/scans/:scanId', userController.updateScan);

// DELETE /api/user/scans/:scanId
router.delete('/user/scans/:scanId', userController.deleteScan);

// GET  /user/upload-llm-photo
router.post('/user/photo-upload', userController.photoUpload);

// GET  /user/llm-ask-question
router.post('/user/llm-ask-question', userController.LLMAskQuestion);

// ─── Guardian binding routes ──────────────────────────────────────────────

// POST /api/user/guardian/bind-request
router.post('/user/guardian/bind-request', userController.requestGuardianBind);

// POST /api/user/guardian/bind-confirm
router.post('/user/guardian/bind-confirm', userController.confirmGuardianBind);

// GET  /api/user/guardian/bound-users
router.get('/user/guardian/bound-users', userController.getBoundUsers);

// GET  /api/user/guardian/scan-stats
router.get('/user/guardian/scan-stats', userController.getScanStats);

// GET  /api/user/guardian/all-scans/user?user_id=<id>
router.get('/user/guardian/all-scans/user', userController.getScansByUser);

// POST /api/user/guardian/llm-ask-question
router.post('/user/guardian/llm-ask-question', userController.guardianLLMAskQuestion);

// POST /api/user/guardian/llm-ask-question
router.post('/user/guardian/llm-ask-question', userController.guardianLLMAskQuestion);

// GET /api/user/guardian/:conversationId/image
router.get('/user/guardian/:conversationId/image', userController.getConversationImage)

// GET /api/user/guardian/conversation/:conversationId/history
router.get('/user/guardian/conversation/:conversationId/history', userController.getConversationHistory)

module.exports = router;