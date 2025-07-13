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

router.post('/admin/users', adminController.createUser);

router.get('/admin/users', adminController.listUsers);

router.get('/admin/users/:userId', adminController.getUserById);

router.put('/admin/users/:userId', adminController.updateUser);

router.delete('/admin/users/:userId', adminController.deleteUser);

router.get('/admin/users/:userId/scans', adminController.getUserScans);

router.put('/admin/scans/:scanId', adminController.updateScan);

router.delete('/admin/scans/:scanId', adminController.deleteScan);

router.get('/admin/dashboard', adminController.getDashboardStats);

router.get('/admin/report', adminController.generateReport);

router.get('/users/:userId/guardians', adminController.getUserGuardians);

router.post('/users/:userId/guardians', adminController.bindGuardian);

router.delete('/users/:userId/guardians/:guardianId', adminController.unbindGuardian);

module.exports = router;
