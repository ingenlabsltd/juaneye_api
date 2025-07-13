const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/authMiddleware');
const userController = require('../controllers/userController');

router.use(verifyToken);

router.get('/user/dashboard', userController.getDashboard);

router.get('/user/profile', userController.getProfile);

router.post('/user/ocr-scans', userController.createOCRScan);

router.post('/user/object-scans', userController.createObjectScan);

router.get('/user/scans', userController.getUserScans);

router.get('/user/scans/:scanId', userController.getSingleScan);

router.put('/user/scans/:scanId', userController.updateScan);

router.delete('/user/scans/:scanId', userController.deleteScan);

router.post('/user/photo-upload', userController.photoUpload);

router.post('/user/llm-ask-question', userController.LLMAskQuestion);

router.get('/user/get-guardians', userController.getUserGuardians);

router.delete('/user/remove-guardian/:guardianId', userController.removeUserGuardian);

router.get('/users/scans/:conversationId/images', userController.getConversationImages);
// ─── Guardian binding routes ──────────────────────────────────────────────

router.post('/user/guardian/bind-request', userController.requestGuardianBind);

router.post('/user/guardian/bind-confirm', userController.confirmGuardianBind);

router.get('/user/guardian/bound-users', userController.getBoundUsers);

router.get('/user/guardian/scan-stats', userController.getScanStats);

router.get('/user/guardian/all-scans/user', userController.getScansByUser);

router.post('/user/guardian/llm-ask-question', userController.guardianLLMAskQuestion);

router.post('/user/guardian/llm-ask-question', userController.guardianLLMAskQuestion);

router.get('/user/guardian/:conversationId/image', userController.getConversationImage)

router.get('/user/guardian/conversation/:conversationId/history', userController.getConversationHistory)

module.exports = router;