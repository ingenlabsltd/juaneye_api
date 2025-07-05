// controllers/userController.js

const pool = require('../db');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

// ─── Helpers for Guardian Binding OTP ─────────────────────────────────────
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTPEmail(toEmail, codeValue) {
    const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
        tls: {
            rejectUnauthorized: false,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: toEmail,
        subject: 'Your Guardian Binding Code',
        text: `Your binding OTP code is: ${codeValue}. Expires in ${process.env.OTP_EXPIRATION_MINUTES} minutes.`,
    };

    await transporter.sendMail(mailOptions);
}

/**
 * GET /api/user/dashboard
 * Returns a welcome message plus the user’s scanCount and premium status.
 */
async function getDashboard(req, res, next) {
    try {
        const { user_id, email, accountType } = req.user;

        const [rows] = await pool.execute(
            `SELECT
         scanCount,
         isPremiumUser
       FROM USERS
       WHERE user_id = ?`,
            [user_id]
        );

        if (!rows.length) {
            return res.status(404).json({ error: 'User not found' });
        }

        const { scanCount, isPremiumUser } = rows[0];

        res.json({
            message: `Welcome to your dashboard, ${email}!`,
            user: {
                user_id,
                email,
                accountType,
                scanCount,
                isPremiumUser: !!isPremiumUser,
            },
        });
    } catch (err) {
        next(err);
    }
}

/**
 * GET /api/user/profile
 * Returns the user’s full profile.
 */
async function getProfile(req, res, next) {
    try {
        const { user_id } = req.user;

        const [rows] = await pool.execute(
            `SELECT
         user_id,
         email,
         accountType,
         isPremiumUser,
         scanCount,
         deviceUuid,
         phone,
         createdAt,
         updatedAt
       FROM USERS
       WHERE user_id = ?`,
            [user_id]
        );

        if (!rows.length) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(rows[0]);
    } catch (err) {
        next(err);
    }
}

/**
 * POST /api/user/ocr-scans
 * Body: { recognizedText, text }
 * Creates a new OCR scan.
 */
async function createOCRScan(req, res, next) {
    try {
        const { user_id } = req.user;
        const { recognizedText, text } = req.body;

        if (typeof recognizedText !== 'string' || typeof text !== 'string') {
            return res.status(400).json({ error: 'recognizedText and text are required strings.' });
        }

        const [result] = await pool.execute(
            `INSERT INTO OCR_SCANS (
         user_id,
         recognizedText,
         text,
         dateTime,
         createdAt,
         updatedAt
       ) VALUES (
         ?, ?, ?, NOW(), NOW(), NOW()
       )`,
            [user_id, recognizedText, text]
        );

        res.status(201).json({
            message: 'OCR scan created.',
            scan: {
                scanId: result.insertId,
                recognizedText,
                text,
            },
        });
    } catch (err) {
        next(err);
    }
}

/**
 * POST /api/user/object-scans
 * Body: { recognizedObjects, text }
 * Creates a new Object scan.
 */
async function createObjectScan(req, res, next) {
    try {
        const { user_id } = req.user;
        const { recognizedObjects, text } = req.body;

        if (typeof recognizedObjects !== 'string' || typeof text !== 'string') {
            return res.status(400).json({ error: 'recognizedObjects and text are required strings.' });
        }

        const [result] = await pool.execute(
            `INSERT INTO OBJECT_SCANS (
         user_id,
         recognizedObjects,
         text,
         createdAt,
         updatedAt
       ) VALUES (
         ?, ?, ?, NOW(), NOW()
       )`,
            [user_id, recognizedObjects, text]
        );

        res.status(201).json({
            message: 'Object scan created.',
            scan: {
                scanId: result.insertId,
                recognizedObjects,
                text,
            },
        });
    } catch (err) {
        next(err);
    }
}

/**
 * GET /api/user/scans
 * Returns all scans for the user or, if Guardian, for bound users.
 */
async function getUserScans(req, res, next) {
    try {
        const { user_id, accountType } = req.user;
        let ids = [user_id];

        if (accountType === 'Guardian') {
            const [links] = await pool.execute(
                `SELECT user_id FROM USER_GUARDIAN_LINK WHERE guardian_id = ?`,
                [user_id]
            );

            ids = links.length ? links.map(r => r.user_id) : ids;
        }

        const placeholderString = ids.map(() => '?').join(',');

        const [rows] = await pool.execute(
            `SELECT
         scan_id AS scanId,
         recognizedObjects AS name,
         text,
         'Object' AS type,
         createdAt
       FROM OBJECT_SCANS
       WHERE user_id IN (${placeholderString})
       UNION ALL
       SELECT
         ocr_id AS scanId,
         recognizedText AS name,
         text,
         'Text' AS type,
         dateTime AS createdAt
       FROM OCR_SCANS
       WHERE user_id IN (${placeholderString})
       ORDER BY createdAt DESC`,
            [...ids, ...ids]
        );

        res.json(rows);
    } catch (err) {
        next(err);
    }
}

/**
 * GET /api/user/scans/:scanId
 * Returns a single scan if authorized.
 */
async function getSingleScan(req, res, next) {
    try {
        const { user_id, accountType } = req.user;
        const scanId = parseInt(req.params.scanId, 10);

        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Invalid scanId' });
        }

        let ids = [user_id];

        if (accountType === 'Guardian') {
            const [links] = await pool.execute(
                `SELECT user_id FROM USER_GUARDIAN_LINK WHERE guardian_id = ?`,
                [user_id]
            );

            ids = links.length ? links.map(r => r.user_id) : ids;
        }

        const placeholderString = ids.map(() => '?').join(',');

        const [ocrRows] = await pool.execute(
            `SELECT
         ocr_id AS scanId,
         recognizedText AS name,
         text,
         dateTime,
         createdAt,
         updatedAt
       FROM OCR_SCANS
       WHERE ocr_id = ? AND user_id IN (${placeholderString})`,
            [scanId, ...ids]
        );

        if (ocrRows.length) {
            return res.json({ type: 'Text', ...ocrRows[0] });
        }

        const [objRows] = await pool.execute(
            `SELECT
         scan_id AS scanId,
         recognizedObjects AS name,
         text,
         createdAt,
         updatedAt
       FROM OBJECT_SCANS
       WHERE scan_id = ? AND user_id IN (${placeholderString})`,
            [scanId, ...ids]
        );

        if (objRows.length) {
            return res.json({ type: 'Object', ...objRows[0] });
        }

        res.status(404).json({ error: 'Scan not found' });
    } catch (err) {
        next(err);
    }
}

/**
 * PUT /api/user/scans/:scanId
 * Body: { type, name, text }
 * Updates a scan if authorized (owner or bound Guardian).
 */
async function updateScan(req, res, next) {
    const conn = await pool.getConnection();
    try {
        const { user_id: requesterId, accountType } = req.user;
        const scanId = parseInt(req.params.scanId, 10);
        const { type, name, text } = req.body;

        if (
            isNaN(scanId) ||
            !['Object', 'Text'].includes(type) ||
            typeof name !== 'string' ||
            typeof text !== 'string'
        ) {
            return res.status(400).json({ error: 'Invalid input' });
        }

        // 1) figure out who owns this scan
        let ownerRows;
        if (type === 'Text') {
            [ownerRows] = await conn.execute(
                `SELECT user_id FROM OCR_SCANS WHERE ocr_id = ?`,
                [scanId]
            );
        } else {
            [ownerRows] = await conn.execute(
                `SELECT user_id FROM OBJECT_SCANS WHERE scan_id = ?`,
                [scanId]
            );
        }

        if (!ownerRows.length) {
            return res.status(404).json({ error: type === 'Text' ? 'OCR scan not found' : 'Object scan not found' });
        }

        const ownerId = ownerRows[0].user_id;

        // 2) check permissions: either you are the owner...
        let allowed = ownerId === requesterId;

        // ...or you are a Guardian bound to that owner
        if (!allowed && accountType === 'Guardian') {
            const [links] = await conn.execute(
                `SELECT 1
                   FROM USER_GUARDIAN_LINK
                  WHERE guardian_id = ?
                    AND user_id     = ?`,
                [requesterId, ownerId]
            );
            allowed = links.length > 0;
        }

        if (!allowed) {
            return res.status(403).json({ error: 'Not authorized to update this scan.' });
        }

        // 3) finally, perform the update
        if (type === 'Text') {
            await conn.execute(
                `UPDATE OCR_SCANS
                    SET recognizedText = ?, text = ?, updatedAt = NOW()
                  WHERE ocr_id = ?`,
                [name, text, scanId]
            );
        } else {
            await conn.execute(
                `UPDATE OBJECT_SCANS
                    SET recognizedObjects = ?, text = ?, updatedAt = NOW()
                  WHERE scan_id = ?`,
                [name, text, scanId]
            );
        }

        res.json({ message: 'Scan updated successfully.' });
    } catch (err) {
        next(err);
    } finally {
        conn.release();
    }
}

/**
 * DELETE /api/user/scans/:scanId
 * Deletes a scan if authorized.
 */
async function deleteScan(req, res, next) {
    try {
        const { user_id } = req.user;
        const scanId = parseInt(req.params.scanId, 10);

        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Invalid scanId' });
        }

        const [ocrDel] = await pool.execute(
            `DELETE FROM OCR_SCANS WHERE ocr_id = ? AND user_id = ?`,
            [scanId, user_id]
        );

        if (ocrDel.affectedRows) {
            return res.json({ message: 'OCR scan deleted.' });
        }

        const [objDel] = await pool.execute(
            `DELETE FROM OBJECT_SCANS WHERE scan_id = ? AND user_id = ?`,
            [scanId, user_id]
        );

        if (objDel.affectedRows) {
            return res.json({ message: 'Object scan deleted.' });
        }

        res.status(404).json({ error: 'Scan not found' });
    } catch (err) {
        next(err);
    }
}

/**
 * POST /api/user/guardian/bind-request
 */
async function requestGuardianBind(req, res, next) {
    try {
        const { user_id, accountType } = req.user;

        if (accountType !== 'Guardian') {
            return res.status(403).json({ error: 'Only Guardians can request binding.' });
        }

        const { email } = req.body;

        if (typeof email !== 'string') {
            return res.status(400).json({ error: 'Email required.' });
        }

        const [users] = await pool.execute(
            `SELECT user_id FROM USERS WHERE email = ?`,
            [email]
        );

        if (!users.length) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const targetId = users[0].user_id;
        const codeValue = generateOTP();
        const expiration = new Date(
            Date.now() + parseInt(process.env.OTP_EXPIRATION_MINUTES, 10) * 60000
        );

        await pool.execute(
            `INSERT INTO OTPS (
         user_id,
         codeValue,
         expirationTime,
         isUsed,
         createdAt,
         updatedAt
       ) VALUES (
         ?, ?, ?, FALSE, NOW(), NOW()
       )`,
            [targetId, codeValue, expiration]
        );

        await sendOTPEmail(email, codeValue);

        res.json({ message: 'OTP sent.' });
    } catch (err) {
        next(err);
    }
}

/**
 * POST /api/user/guardian/bind-confirm
 */
async function confirmGuardianBind(req, res, next) {
    const conn = await pool.getConnection();

    try {
        const { user_id: guardianId, accountType } = req.user;
        if (accountType !== 'Guardian') {
            conn.release();
            return res.status(403).json({ error: 'Only Guardians can confirm.' });
        }

        const { email, codeValue } = req.body;
        if (typeof email !== 'string' || typeof codeValue !== 'string') {
            conn.release();
            return res.status(400).json({ error: 'Invalid input.' });
        }

        // 1) lookup target user
        const [users] = await conn.execute(
            `SELECT user_id FROM USERS WHERE email = ?`,
            [email]
        );
        if (!users.length) {
            conn.release();
            return res.status(404).json({ error: 'User not found.' });
        }
        const targetId = users[0].user_id;

        // 2) verify OTP
        const [otps] = await conn.execute(
            `SELECT otp_id, expirationTime
             FROM OTPS
             WHERE user_id = ? AND codeValue = ? AND isUsed = FALSE
             ORDER BY createdAt DESC
                 LIMIT 1`,
            [targetId, codeValue]
        );
        if (!otps.length) {
            conn.release();
            return res.status(400).json({ error: 'OTP invalid/expired.' });
        }
        if (new Date(otps[0].expirationTime) < new Date()) {
            conn.release();
            return res.status(400).json({ error: 'OTP expired.' });
        }

        // 3) check for existing binding
        const [existing] = await conn.execute(
            `SELECT 1
         FROM USER_GUARDIAN_LINK
        WHERE user_id = ? AND guardian_id = ?`,
            [targetId, guardianId]
        );
        if (existing.length) {
            conn.release();
            return res.status(409).json({ error: 'Already bound to this user.' });
        }

        // 4) mark OTP used and insert binding
        await conn.beginTransaction();
        await conn.execute(
            `UPDATE OTPS
             SET isUsed = TRUE, updatedAt = NOW()
             WHERE otp_id = ?`,
            [otps[0].otp_id]
        );
        await conn.execute(
            `INSERT INTO USER_GUARDIAN_LINK (
                user_id,
                guardian_id,
                linkedOn
            ) VALUES (
                         ?, ?, NOW()
                     )`,
            [targetId, guardianId]
        );
        await conn.commit();
        conn.release();

        res.json({ message: 'Guardian bound.' });
    } catch (err) {
        await conn.rollback();
        conn.release();
        next(err);
    }
}

/**
 * GET /api/user/guardian/bound-users
 */
async function getBoundUsers(req, res, next) {
    try {
        const { user_id, accountType } = req.user;

        if (accountType !== 'Guardian') {
            return res.status(403).json({ error: 'Only Guardians can view.' });
        }

        const [rows] = await pool.execute(
            `SELECT
         u.user_id,
         u.email
       FROM USER_GUARDIAN_LINK l
       JOIN USERS u ON u.user_id = l.user_id
       WHERE l.guardian_id = ?`,
            [user_id]
        );

        res.json(rows);
    } catch (err) {
        next(err);
    }
}

/**
 * GET /api/user/scans/user
 * Query: ?user_id=<number>
 * Returns scans for a specific user if requester is that user or bound Guardian.
 */
async function getScansByUser(req, res, next) {
    try {
        const { user_id: requesterId, accountType } = req.user;
        const targetId = parseInt(req.query.user_id, 10);

        if (isNaN(targetId)) {
            return res.status(400).json({ error: 'Invalid user_id.' });
        }

        if (targetId !== requesterId) {
            if (accountType !== 'Guardian') {
                return res.status(403).json({ error: 'Not authorized.' });
            }

            const [link] = await pool.execute(
                `SELECT 1 FROM USER_GUARDIAN_LINK
         WHERE guardian_id = ? AND user_id = ?`,
                [requesterId, targetId]
            );

            if (!link.length) {
                return res.status(403).json({ error: 'Not bound.' });
            }
        }

        const [rows] = await pool.execute(
            `SELECT
                 scan_id AS scanId,
                 recognizedObjects AS name,
                 text,
                 'Object' AS type,
                 createdAt
             FROM OBJECT_SCANS
             WHERE user_id = ?
             UNION ALL
             SELECT
                 ocr_id AS scanId,
                 recognizedText AS name,
                 text,
                 'Text' AS type,
                 dateTime AS createdAt
             FROM OCR_SCANS
             WHERE user_id = ?
             ORDER BY createdAt DESC`,
            [targetId, targetId]
        );

        res.json(rows);
    } catch (err) {
        next(err);
    }
}

/**
 * GET /api/user/guardian/scan-stats
 * Query params (optional): startDate=YYYY-MM-DD, endDate=YYYY-MM-DD
 * Returns aggregated counts for bound users over the given date range.
 * Defaults to today 00:00:00 → now.
 */
async function getScanStats(req, res, next) {
    try {
        const { user_id: guardianId, accountType } = req.user;
        if (accountType !== 'Guardian') {
            return res.status(403).json({ error: 'Only Guardians can view stats.' });
        }

        // parse dates or default to today
        const today = new Date();
        const start = req.query.startDate
            ? new Date(String(req.query.startDate))
            : new Date(today.getFullYear(), today.getMonth(), today.getDate());
        const end = req.query.endDate
            ? new Date(String(req.query.endDate))
            : today;

        // get the list of bound user IDs
        const [links] = await pool.execute(
            `SELECT user_id FROM USER_GUARDIAN_LINK WHERE guardian_id = ?`,
            [guardianId]
        );
        const userIds = links.map(r => r.user_id);
        if (userIds.length === 0) {
            return res.json({ objectScanCount: 0, ocrScanCount: 0 });
        }

        const placeholders = userIds.map(() => '?').join(',');
        // count object scans
        const [objRows] = await pool.execute(
            `SELECT COUNT(*) AS objectScanCount
         FROM OBJECT_SCANS
        WHERE user_id IN (${placeholders})
          AND createdAt BETWEEN ? AND ?`,
            [...userIds, start, end]
        );
        // count OCR scans
        const [ocrRows] = await pool.execute(
            `SELECT COUNT(*) AS ocrScanCount
         FROM OCR_SCANS
        WHERE user_id IN (${placeholders})
          AND dateTime BETWEEN ? AND ?`,
            [...userIds, start, end]
        );

        res.json({
            objectScanCount: objRows[0].objectScanCount,
            ocrScanCount: ocrRows[0].ocrScanCount,
        });
    } catch (err) {
        next(err);
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
    deleteScan,
    requestGuardianBind,
    confirmGuardianBind,
    getBoundUsers,
    getScansByUser,
    getScanStats,
};
