// controllers/userController.js

const pool = require('../db');

/**
 * GET /api/user/dashboard
 * Returns a welcome message plus the user’s own scanCount and premium status.
 */
async function getDashboard(req, res, next) {
    try {
        const { user_id, email, accountType } = req.user;
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
}

/**
 * GET /api/user/profile
 * Returns the user’s full profile row.
 */
async function getProfile(req, res, next) {
    try {
        const { user_id } = req.user;
        const [rows] = await pool.execute(
            `SELECT user_id, email, accountType, isPremiumUser, scanCount, deviceUuid, phone, createdAt, updatedAt
             FROM USERS
             WHERE user_id = ?`,
            [user_id]
        );
        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        return res.json(rows[0]);
    } catch (err) {
        return next(err);
    }
}

/**
 * POST /api/user/ocr-scans
 * Body: { recognizedText: string, text: string }
 * Creates a new OCR scan for the authenticated user.
 */
async function createOCRScan(req, res, next) {
    try {
        const { user_id } = req.user;
        const { recognizedText, text } = req.body;

        if (typeof recognizedText !== 'string' || typeof text !== 'string') {
            return res.status(400).json({
                error: 'Request body must include recognizedText (string) and text (string).'
            });
        }

        const [result] = await pool.execute(
            `INSERT INTO OCR_SCANS
         (user_id, recognizedText, text, dateTime, createdAt, updatedAt)
       VALUES (?, ?, ?, NOW(), NOW(), NOW())`,
            [user_id, recognizedText, text]
        );

        const newScanId = result.insertId;
        return res.status(201).json({
            message: 'OCR scan created successfully.',
            scan: {
                scanId: newScanId,
                recognizedText,
                text
            }
        });
    } catch (err) {
        return next(err);
    }
}

/**
 * POST /api/user/object-scans
 * Body: { recognizedObjects: string, text: string }
 * Creates a new Object scan for the authenticated user.
 */
async function createObjectScan(req, res, next) {
    try {
        const { user_id } = req.user;
        const { recognizedObjects, text } = req.body;

        if (typeof recognizedObjects !== 'string' || typeof text !== 'string') {
            return res.status(400).json({
                error: 'Request body must include recognizedObjects (string) and text (string).'
            });
        }

        const [result] = await pool.execute(
            `INSERT INTO OBJECT_SCANS
         (user_id, recognizedObjects, text, createdAt, updatedAt)
       VALUES (?, ?, ?, NOW(), NOW())`,
            [user_id, recognizedObjects, text]
        );

        const newScanId = result.insertId;
        return res.status(201).json({
            message: 'Object scan created successfully.',
            scan: {
                scanId: newScanId,
                recognizedObjects,
                text
            }
        });
    } catch (err) {
        return next(err);
    }
}

/**
 * GET /api/user/scans
 * Returns all OCR and Object scans belonging to the authenticated user, sorted by createdAt DESC.
 * Response: [
 *   { scanId, name, text, type: 'Object' | 'Text', createdAt },
 *   ...
 * ]
 */
async function getUserScans(req, res, next) {
    try {
        const { user_id } = req.user;
        const [rows] = await pool.execute(
            `SELECT
         scan_id           AS scanId,
         recognizedObjects AS name,
         text              AS text,
         'Object'          AS type,
         createdAt
       FROM OBJECT_SCANS
       WHERE user_id = ?
       UNION ALL
       SELECT
         ocr_id            AS scanId,
         recognizedText    AS name,
         text              AS text,
         'Text'            AS type,
         createdAt
       FROM OCR_SCANS
       WHERE user_id = ?
       ORDER BY createdAt DESC`,
            [user_id, user_id]
        );
        return res.json(rows);
    } catch (err) {
        return next(err);
    }
}

/**
 * GET /api/user/scans/:scanId
 * Returns details for a single scan — either from OCR_SCANS or OBJECT_SCANS — if it belongs to the user.
 */
async function getSingleScan(req, res, next) {
    try {
        const { user_id } = req.user;
        const scanId = parseInt(req.params.scanId);
        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Invalid scanId parameter' });
        }

        // 1) Try OCR_SCANS
        const [ocrRows] = await pool.execute(
            `SELECT
         ocr_id AS scanId,
         recognizedText AS name,
         text,
         dateTime,
         createdAt,
         updatedAt
       FROM OCR_SCANS
       WHERE ocr_id = ? AND user_id = ?`,
            [scanId, user_id]
        );
        if (ocrRows.length > 0) {
            return res.json({ type: 'Text', ...ocrRows[0] });
        }

        // 2) Otherwise try OBJECT_SCANS
        const [objRows] = await pool.execute(
            `SELECT
         scan_id AS scanId,
         recognizedObjects AS name,
         text,
         createdAt,
         updatedAt
       FROM OBJECT_SCANS
       WHERE scan_id = ? AND user_id = ?`,
            [scanId, user_id]
        );
        if (objRows.length > 0) {
            return res.json({ type: 'Object', ...objRows[0] });
        }

        // 3) Not found
        return res.status(404).json({ error: 'Scan not found' });
    } catch (err) {
        return next(err);
    }
}

/**
 * PUT /api/user/scans/:scanId
 * Body: { type: 'Object' | 'Text', name: string, text: string }
 * Updates an existing scan (OCR or Object) if it belongs to the user.
 */
async function updateScan(req, res, next) {
    try {
        const { user_id } = req.user;
        const scanId = parseInt(req.params.scanId);
        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Invalid scanId parameter' });
        }

        const { type, name, text } = req.body;
        if (!['Object', 'Text'].includes(type) || typeof name !== 'string' || typeof text !== 'string') {
            return res.status(400).json({
                error: "Request body must include type ('Object' or 'Text'), name (string), and text (string)."
            });
        }

        if (type === 'Text') {
            // Check that the OCR scan exists and belongs to this user
            const [check] = await pool.execute(
                `SELECT ocr_id FROM OCR_SCANS WHERE ocr_id = ? AND user_id = ?`,
                [scanId, user_id]
            );
            if (check.length === 0) {
                return res.status(404).json({ error: 'OCR scan not found or does not belong to user.' });
            }

            // Update the OCR_SCANS row
            await pool.execute(
                `UPDATE OCR_SCANS
         SET recognizedText = ?, text = ?, updatedAt = NOW()
         WHERE ocr_id = ?`,
                [name, text, scanId]
            );
            return res.json({ message: 'OCR scan updated successfully.' });
        } else {
            // Check that the Object scan exists and belongs to this user
            const [check] = await pool.execute(
                `SELECT scan_id FROM OBJECT_SCANS WHERE scan_id = ? AND user_id = ?`,
                [scanId, user_id]
            );
            if (check.length === 0) {
                return res.status(404).json({ error: 'Object scan not found or does not belong to user.' });
            }

            // Update the OBJECT_SCANS row
            await pool.execute(
                `UPDATE OBJECT_SCANS
         SET recognizedObjects = ?, text = ?, updatedAt = NOW()
         WHERE scan_id = ?`,
                [name, text, scanId]
            );
            return res.json({ message: 'Object scan updated successfully.' });
        }
    } catch (err) {
        return next(err);
    }
}

/**
 * DELETE /api/user/scans/:scanId
 * Deletes a scan (OCR or Object) if it belongs to the user.
 */
async function deleteScan(req, res, next) {
    try {
        const { user_id } = req.user;
        const scanId = parseInt(req.params.scanId);
        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Invalid scanId parameter' });
        }

        // 1) Try deleting from OCR_SCANS
        const [ocrDelete] = await pool.execute(
            `DELETE FROM OCR_SCANS
       WHERE ocr_id = ? AND user_id = ?`,
            [scanId, user_id]
        );
        if (ocrDelete.affectedRows > 0) {
            return res.json({ message: 'OCR scan deleted successfully.' });
        }

        // 2) Try deleting from OBJECT_SCANS
        const [objDelete] = await pool.execute(
            `DELETE FROM OBJECT_SCANS
       WHERE scan_id = ? AND user_id = ?`,
            [scanId, user_id]
        );
        if (objDelete.affectedRows > 0) {
            return res.json({ message: 'Object scan deleted successfully.' });
        }

        // 3) Neither found
        return res.status(404).json({ error: 'Scan not found or does not belong to user.' });
    } catch (err) {
        return next(err);
    }
}

module.exports = {
    getDashboard,
    getProfile,
    createOCRScan,
    createObjectScan,
    getUserScans,
    getSingleScan,
    updateScan,
    deleteScan
};
