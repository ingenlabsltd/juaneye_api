// controllers/userController.js

const pool = require('../db');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');

dotenv.config();

// ─── Helpers for Guardian Binding OTP ─────────────────────────────────────-
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

const imageStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        // first try authenticated user
        let email = req.user && typeof req.user.email === 'string'
            ? req.user.email
            : null;

        // fallback: load email from DB by user_id
        if (!email) {
            const userId = req.user && req.user.user_id;
            if (!userId) {
                return cb(new Error('User ID not available for upload path'), null);
            }
            return pool.execute(
                `SELECT email
                         FROM USERS
                         WHERE user_id = ?`,
                [userId]
            ).then(([rows]) => {
                if (!rows.length || typeof rows[0].email !== 'string') {
                    throw new Error('User not found for upload path');
                }
                email = rows[0].email;
                const dateFolder = new Date().toISOString().split('T')[0];
                const uploadDir = path.join(__dirname, '..', 'uploads', email, dateFolder);
                fs.mkdirSync(uploadDir, {recursive: true});
                cb(null, uploadDir);
            }).catch(err => {
                cb(err, null);
            });
        }

        // use today's date as folder name
        const dateFolder = new Date().toISOString().split('T')[0];
        const uploadDir = path.join(__dirname, '..', 'uploads', email, dateFolder);
        fs.mkdirSync(uploadDir, {recursive: true});
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // timestamp + original name
        const uniqueName = `${Date.now()}-${file.originalname}`;
        cb(null, uniqueName);
    },
});

const upload = multer({
        storage: imageStorage,
        fileFilter: (req, file, cb) => {
            const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'];
            const ext = path.extname(file.originalname).toLowerCase();
            if (!allowed.includes(ext)) {
                return cb(new Error('Only image files allowed.'));
            }
            cb(null, true);
        },
    }).single('media');

module.exports = {
        /**
         * GET /api/user/dashboard
         * Returns a welcome message plus the user’s scanCount and premium status.
         */
        getDashboard: async (req, res, next) => {
            try {
                const {user_id, email, accountType} = req.user;

                const [rows] = await pool.execute(
                    `SELECT scanCount,
                            isPremiumUser
                     FROM USERS
                     WHERE user_id = ?`,
                    [user_id]
                );

                if (!rows.length) {
                    return res.status(404).json({error: 'User not found'});
                }

                const {scanCount, isPremiumUser} = rows[0];

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
        },

        /**
         * GET /api/user/profile
         * Returns the user’s full profile.
         */
        getProfile: async (req, res, next) => {
            try {
                const {user_id} = req.user;

                const [rows] = await pool.execute(
                    `SELECT user_id,
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
                    return res.status(404).json({error: 'User not found'});
                }

                res.json(rows[0]);
            } catch (err) {
                next(err);
            }
        },

        /**
         * POST /api/user/ocr-scans
         * Body: { recognizedText, text }
         * Creates a new OCR scan.
         */
        createOCRScan: async (req, res, next) => {
            try {
                const {user_id} = req.user;
                const {recognizedText, text} = req.body;

                if (typeof recognizedText !== 'string' || typeof text !== 'string') {
                    return res.status(400).json({error: 'recognizedText and text are required strings.'});
                }

                const [result] = await pool.execute(
                    `INSERT INTO OCR_SCANS (user_id,
                                            recognizedText,
                                            text,
                                            dateTime,
                                            createdAt,
                                            updatedAt)
                     VALUES (?, ?, ?, NOW(), NOW(), NOW())`,
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
        },

        /**
         * POST /api/user/object-scans
         * Body: { recognizedObjects, text }
         * Creates a new Object scan.
         */
        createObjectScan: async (req, res, next) => {
            try {
                const {user_id} = req.user;
                const {recognizedObjects, text} = req.body;

                if (typeof recognizedObjects !== 'string' || typeof text !== 'string') {
                    return res.status(400).json({error: 'recognizedObjects and text are required strings.'});
                }

                const [result] = await pool.execute(
                    `INSERT INTO OBJECT_SCANS (user_id,
                                               recognizedObjects,
                                               text,
                                               createdAt,
                                               updatedAt)
                     VALUES (?, ?, ?, NOW(), NOW())`,
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
        },

        /**
         * GET /api/user/scans
         * Returns all scans for the user or, if Guardian, for bound users.
         */
        getUserScans: async (req, res, next) => {
            try {
                const {user_id, accountType} = req.user;
                let ids = [user_id];

                if (accountType === 'Guardian') {
                    const [links] = await pool.execute(
                        `SELECT user_id
                         FROM USER_GUARDIAN_LINK
                         WHERE guardian_id = ?`,
                        [user_id]
                    );

                    ids = links.length ? links.map(r => r.user_id) : ids;
                }

                const placeholderString = ids.map(() => '?').join(',');

                const [rows] = await pool.execute(
                    `SELECT scan_id           AS scanId,
                            recognizedObjects AS name,
                            text,
                            'Object'          AS type,
                            createdAt
                     FROM OBJECT_SCANS
                     WHERE user_id IN (${placeholderString})
                     UNION ALL
                     SELECT ocr_id         AS scanId,
                            recognizedText AS name,
                            text,
                            'Text'         AS type,
                            dateTime       AS createdAt
                     FROM OCR_SCANS
                     WHERE user_id IN (${placeholderString})
                     ORDER BY createdAt DESC`,
                    [...ids, ...ids]
                );

                res.json(rows);
            } catch (err) {
                next(err);
            }
        },

        /**
         * GET /api/user/scans/:scanId
         * Returns a single scan if authorized.
         */
        getSingleScan: async (req, res, next) => {
            try {
                const {user_id, accountType} = req.user;
                const scanId = parseInt(req.params.scanId, 10);

                if (isNaN(scanId)) {
                    return res.status(400).json({error: 'Invalid scanId'});
                }

                let ids = [user_id];

                if (accountType === 'Guardian') {
                    const [links] = await pool.execute(
                        `SELECT user_id
                         FROM USER_GUARDIAN_LINK
                         WHERE guardian_id = ?`,
                        [user_id]
                    );

                    ids = links.length ? links.map(r => r.user_id) : ids;
                }

                const placeholderString = ids.map(() => '?').join(',');

                const [ocrRows] = await pool.execute(
                    `SELECT ocr_id         AS scanId,
                            recognizedText AS name,
                            text,
                            dateTime,
                            createdAt,
                            updatedAt
                     FROM OCR_SCANS
                     WHERE ocr_id = ?
                       AND user_id IN (${placeholderString})`,
                    [scanId, ...ids]
                );

                if (ocrRows.length) {
                    return res.json({type: 'Text', ...ocrRows[0]});
                }

                const [objRows] = await pool.execute(
                    `SELECT scan_id           AS scanId,
                            recognizedObjects AS name,
                            text,
                            createdAt,
                            updatedAt
                     FROM OBJECT_SCANS
                     WHERE scan_id = ?
                       AND user_id IN (${placeholderString})`,
                    [scanId, ...ids]
                );

                if (objRows.length) {
                    return res.json({type: 'Object', ...objRows[0]});
                }

                res.status(404).json({error: 'Scan not found'});
            } catch (err) {
                next(err);
            }
        },

        /**
         * GET /api/user/get-guardians
         * Returns all Guardians bound to this user, including their emails.
         */
        getUserGuardians: async (req, res, next) => {
            try {
                const userId = req.user.user_id;

                const [rows] = await pool.execute(
                    `SELECT u.user_id AS guardianId,
                            u.email   AS guardianEmail
                     FROM USER_GUARDIAN_LINK l
                              JOIN USERS u
                                   ON u.user_id = l.guardian_id
                     WHERE l.user_id = ?`,
                    [userId]
                );

                res.json(rows);
            } catch (err) {
                next(err);
            }
        },

        /**
         * DELETE /api/user/remove-guardian/:guardianId
         * Removes a bound Guardian from this user.
         */
        removeUserGuardian: async (req, res, next) => {
            try {
                const userId = req.user.user_id;
                const guardianId = parseInt(req.params.guardianId, 10);

                if (isNaN(guardianId)) {
                    return res.status(400).json({error: 'Invalid guardianId parameter.'});
                }

                const [result] = await pool.execute(
                    `DELETE
                     FROM USER_GUARDIAN_LINK
                     WHERE user_id = ?
                       AND guardian_id = ?`,
                    [userId, guardianId]
                );

                if (!result.affectedRows) {
                    return res.status(404).json({error: 'No such Guardian binding found.'});
                }

                res.json({message: 'Guardian removed successfully.'});
            } catch (err) {
                next(err);
            }
        },

        /**
         * PUT /api/user/scans/:scanId
         * Body: { type, name, text }
         * Updates a scan if authorized (owner or bound Guardian).
         */
        updateScan: async (req, res, next) => {
            const conn = await pool.getConnection();
            try {
                const {user_id: requesterId, accountType} = req.user;
                const scanId = parseInt(req.params.scanId, 10);
                const {type, name, text} = req.body;

                if (
                    isNaN(scanId) ||
                    !['Object', 'Text'].includes(type) ||
                    typeof name !== 'string' ||
                    typeof text !== 'string'
                ) {
                    return res.status(400).json({error: 'Invalid input'});
                }

                // 1) figure out who owns this scan
                let ownerRows;
                if (type === 'Text') {
                    [ownerRows] = await conn.execute(
                        `SELECT user_id
                         FROM OCR_SCANS
                         WHERE ocr_id = ?`,
                        [scanId]
                    );
                } else {
                    [ownerRows] = await conn.execute(
                        `SELECT user_id
                         FROM OBJECT_SCANS
                         WHERE scan_id = ?`,
                        [scanId]
                    );
                }

                if (!ownerRows.length) {
                    return res.status(404).json({error: type === 'Text' ? 'OCR scan not found' : 'Object scan not found'});
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
                           AND user_id = ?`,
                        [requesterId, ownerId]
                    );
                    allowed = links.length > 0;
                }

                if (!allowed) {
                    return res.status(403).json({error: 'Not authorized to update this scan.'});
                }

                // 3) finally, perform the update
                if (type === 'Text') {
                    await conn.execute(
                        `UPDATE OCR_SCANS
                         SET recognizedText = ?,
                             text = ?,
                             updatedAt = NOW()
                         WHERE ocr_id = ?`,
                        [name, text, scanId]
                    );
                } else {
                    await conn.execute(
                        `UPDATE OBJECT_SCANS
                         SET recognizedObjects = ?,
                             text = ?,
                             updatedAt = NOW()
                         WHERE scan_id = ?`,
                        [name, text, scanId]
                    );
                }

                res.json({message: 'Scan updated successfully.'});
            } catch (err) {
                next(err);
            } finally {
                conn.release();
            }
        },

        /**
         * DELETE /api/user/scans/:scanId
         * Deletes a scan if authorized.
         */
        deleteScan: async (req, res, next) => {
            try {
                const {user_id} = req.user;
                const scanId = parseInt(req.params.scanId, 10);

                if (isNaN(scanId)) {
                    return res.status(400).json({error: 'Invalid scanId'});
                }

                const [ocrDel] = await pool.execute(
                    `DELETE
                     FROM OCR_SCANS
                     WHERE ocr_id = ?
                       AND user_id = ?`,
                    [scanId, user_id]
                );

                if (ocrDel.affectedRows) {
                    return res.json({message: 'OCR scan deleted.'});
                }

                const [objDel] = await pool.execute(
                    `DELETE
                     FROM OBJECT_SCANS
                     WHERE scan_id = ?
                       AND user_id = ?`,
                    [scanId, user_id]
                );

                if (objDel.affectedRows) {
                    return res.json({message: 'Object scan deleted.'});
                }

                res.status(404).json({error: 'Scan not found'});
            } catch (err) {
                next(err);
            }
        },

        /**
         * POST /api/user/guardian/bind-request
         */
        requestGuardianBind: async (req, res, next) => {
            try {
                const {user_id, accountType} = req.user;

                if (accountType !== 'Guardian') {
                    return res.status(403).json({error: 'Only Guardians can request binding.'});
                }

                const {email} = req.body;

                if (typeof email !== 'string') {
                    return res.status(400).json({error: 'Email required.'});
                }

                const [users] = await pool.execute(
                    `SELECT user_id
                     FROM USERS
                     WHERE email = ?`,
                    [email]
                );

                if (!users.length) {
                    return res.status(404).json({error: 'User not found.'});
                }

                const targetId = users[0].user_id;
                const codeValue = generateOTP();
                const expiration = new Date(
                    Date.now() + parseInt(process.env.OTP_EXPIRATION_MINUTES, 10) * 60000
                );

                await pool.execute(
                    `INSERT INTO OTPS (user_id,
                                       codeValue,
                                       expirationTime,
                                       isUsed,
                                       createdAt,
                                       updatedAt)
                     VALUES (?, ?, ?, FALSE, NOW(), NOW())`,
                    [targetId, codeValue, expiration]
                );

                await sendOTPEmail(email, codeValue);

                res.json({message: 'OTP sent.'});
            } catch (err) {
                next(err);
            }
        },

        /**
         * POST /api/user/guardian/bind-confirm
         */
        confirmGuardianBind: async (req, res, next) => {
            const conn = await pool.getConnection();

            try {
                const {user_id: guardianId, accountType} = req.user;
                if (accountType !== 'Guardian') {
                    conn.release();
                    return res.status(403).json({error: 'Only Guardians can confirm.'});
                }

                const {email, codeValue} = req.body;
                if (typeof email !== 'string' || typeof codeValue !== 'string') {
                    conn.release();
                    return res.status(400).json({error: 'Invalid input.'});
                }

                // 1) lookup target user
                const [users] = await conn.execute(
                    `SELECT user_id
                     FROM USERS
                     WHERE email = ?`,
                    [email]
                );
                if (!users.length) {
                    conn.release();
                    return res.status(404).json({error: 'User not found.'});
                }
                const targetId = users[0].user_id;

                // 2) verify OTP
                const [otps] = await conn.execute(
                    `SELECT otp_id, expirationTime
                     FROM OTPS
                     WHERE user_id = ?
                       AND codeValue = ?
                       AND isUsed = FALSE
                     ORDER BY createdAt DESC LIMIT 1`,
                    [targetId, codeValue]
                );
                if (!otps.length) {
                    conn.release();
                    return res.status(400).json({error: 'OTP invalid/expired.'});
                }
                if (new Date(otps[0].expirationTime) < new Date()) {
                    conn.release();
                    return res.status(400).json({error: 'OTP expired.'});
                }

                // 3) check for existing binding
                const [existing] = await conn.execute(
                    `SELECT 1
                     FROM USER_GUARDIAN_LINK
                     WHERE user_id = ?
                       AND guardian_id = ?`,
                    [targetId, guardianId]
                );
                if (existing.length) {
                    conn.release();
                    return res.status(409).json({error: 'Already bound to this user.'});
                }

                // 4) mark OTP used and insert binding
                await conn.beginTransaction();
                await conn.execute(
                    `UPDATE OTPS
                     SET isUsed = TRUE,
                         updatedAt = NOW()
                     WHERE otp_id = ?`,
                    [otps[0].otp_id]
                );
                await conn.execute(
                    `INSERT INTO USER_GUARDIAN_LINK (user_id,
                                                     guardian_id,
                                                     linkedOn)
                     VALUES (?, ?, NOW())`,
                    [targetId, guardianId]
                );
                await conn.commit();
                conn.release();

                res.json({message: 'Guardian bound.'});
            } catch (err) {
                await conn.rollback();
                conn.release();
                next(err);
            }
        },

        /**
         * GET /api/user/guardian/bound-users
         */
        getBoundUsers: async (req, res, next) => {
            try {
                const {user_id, accountType} = req.user;

                if (accountType !== 'Guardian') {
                    return res.status(403).json({error: 'Only Guardians can view.'});
                }

                const [rows] = await pool.execute(
                    `SELECT u.user_id,
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
        },

        /**
         * GET /api/user/guardian/scans/user
         * Query: ?user_id=<number>
         * Returns:
         *  - all Object/OCR scans for that user (or bound users, if you’re a Guardian), AND
         *  - all LLM conversation threads (id + first user message), labeled type="LLM"
         * in a single combined array, sorted by createdAt descending.
         */
        getScansByUser: async (req, res, next) => {
            try {
                const {user_id: requesterId, accountType, isPremiumUser} = req.user;
                const targetId = parseInt(req.query.user_id, 10);

                if (isNaN(targetId)) {
                    return res.status(400).json({error: 'Invalid user_id.'});
                }

                if (targetId !== requesterId) {
                    if (accountType !== 'Guardian') {
                        return res.status(403).json({error: 'Not authorized.'});
                    }
                    const [link] = await pool.execute(
                        `SELECT 1
                         FROM USER_GUARDIAN_LINK
                         WHERE guardian_id = ?
                           AND user_id = ?`,
                        [requesterId, targetId]
                    );
                    if (!link.length) {
                        return res.status(403).json({error: 'Not bound.'});
                    }
                }

                const [targetRows] = await pool.execute(
                    `SELECT isPremiumUser
                     FROM USERS
                     WHERE user_id = ?`,
                    [targetId]
                );

                if (!targetRows.length || targetRows[0].isPremiumUser !== 1) {
                    return res.status(403).json({error: 'Premium subscription required.'});
                }

                // 1) fetch object & OCR scans
                const [scanRows] = await pool.execute(
                    `SELECT scan_id           AS scanId,
                            recognizedObjects AS name,
                            text,
                            'Object'          AS type,
                            createdAt
                     FROM OBJECT_SCANS
                     WHERE user_id = ?
                     UNION ALL
                     SELECT ocr_id         AS scanId,
                            recognizedText AS name,
                            text,
                            'Text'         AS type,
                            dateTime       AS createdAt
                     FROM OCR_SCANS
                     WHERE user_id = ?
                     ORDER BY createdAt DESC`,
                    [targetId, targetId]
                );

                // 2) fetch LLM conversation summaries (first user message), *only* for this user
                const [convoRows] = await pool.execute(
                    `SELECT ucm.id,
                            ucm.conversation_id,
                            ucm.content AS first_user_message,
                            CASE
                                WHEN acm.content IS NOT NULL
                                    THEN TRIM(SUBSTRING_INDEX(acm.content, '\n\n', -3))
                                ELSE NULL
                                END     AS first_assistant_message,
                            'LLM'       AS type,
                            ucm.createdAt
                     FROM (SELECT conversation_id,
                                  MIN(createdAt) AS firstAt
                           FROM CONVERSATION_MESSAGES
                           WHERE role = 'user'
                             AND user_id = ?
                           GROUP BY conversation_id) AS t
                              JOIN CONVERSATION_MESSAGES AS ucm
                                   ON ucm.conversation_id = t.conversation_id
                                       AND ucm.createdAt = t.firstAt
                                       AND ucm.role = 'user'
                              LEFT JOIN CONVERSATION_MESSAGES AS acm
                                        ON acm.conversation_id = ucm.conversation_id
                                            AND acm.role = 'assistant'
                                            AND acm.createdAt = (SELECT MIN(createdAt)
                                                                 FROM CONVERSATION_MESSAGES
                                                                 WHERE role = 'assistant'
                                                                   AND conversation_id = ucm.conversation_id
                                                                   AND createdAt > ucm.createdAt)
                     ORDER BY ucm.createdAt DESC`,
                    [targetId]
                );

                // 3) merge & sort everything
                const combined = [...scanRows, ...convoRows].sort((a, b) =>
                    new Date(b.createdAt) - new Date(a.createdAt)
                );

                res.json(combined);
            } catch (err) {
                next(err);
            }
        },

        /**
         * GET /api/user/guardian/scan-stats
         * Query params (optional): startDate=YYYY-MM-DD, endDate=YYYY-MM-DD
         * Returns aggregated counts for bound users over the given date range.
         * Defaults to today 00:00:00 → now.
         */
        getScanStats: async (req, res, next) => {
            try {
                const {user_id: guardianId, accountType} = req.user;
                if (accountType !== 'Guardian') {
                    return res.status(403).json({error: 'Only Guardians can view stats.'});
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
                    `SELECT user_id
                     FROM USER_GUARDIAN_LINK
                     WHERE guardian_id = ?`,
                    [guardianId]
                );
                const userIds = links.map(r => r.user_id);
                if (userIds.length === 0) {
                    return res.json({objectScanCount: 0, ocrScanCount: 0});
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
        },

        /**
         * POST /api/user/photo-upload
         * Body: { title, description }, File: media ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp')
         */
        photoUpload: async (req, res, next) => {
            upload(req, res, async function (err) {
            if (err) return res.status(400).json({error: err.message});

            try {
                const userId = req.user.user_id;
                const email = req.user.email || req.body.email;
                if (typeof email !== 'string') {
                    return res.status(400).json({error: 'User email is required.'});
                }

                const {description} = req.body;

                // single-file check
                if (!req.file) {
                    return res.status(400).json({error: 'Media file is required.'});
                }

                // build relative path
                const dateFolder = new Date().toISOString().split('T')[0];
                const relativePath = path.join('uploads', email, dateFolder, req.file.filename);

                // insert one row
                const [result] = await pool.execute(
                    `INSERT INTO LLM_SCANS (user_id,
                                            description,
                                            filePath,
                                            createdAt,
                                            updatedAt)
                     VALUES (?, ?, ?, NOW(), NOW())`,
                    [userId, description, relativePath]
                );

                res.status(201).json({
                    message: 'LLM scan created.',
                    llm_id: result.insertId,
                    file: path.join(email, dateFolder, req.file.filename),
                });
            } catch (error) {
                next(error);
            }
        });
    },


    /**
     * POST /api/user/llm-ask-question
     */
    LLMAskQuestion: async (req, res, next) => {
        try {
            const userId = req.user.user_id;
            // 6900XT Personal PC
            const apiUrl = 'https://llm.ingen.com.ph/api/chat';
            let {conversationId, content, base64, isStream} = req.body;

            if (typeof content !== 'string' || !content.trim()) {
                return res.status(400).json({error: 'content is required.'});
            }

            // 1) ensure conversationId
            if (typeof conversationId !== 'string' || !conversationId.trim()) {
                conversationId = uuidv4();
            }

            // 2) load previous messages
            const [rows] = await pool.execute(
                `SELECT role, content, images
                 FROM CONVERSATION_MESSAGES
                 WHERE conversation_id = ?
                   AND user_id = ?
                 ORDER BY createdAt ASC LIMIT 50`,
                [conversationId, userId]
            );

            const messages = [];
            let usedHistoryImage = false;

            messages.push({
                role: 'system',
                content: [
                    `Say <speak>Hello, Im <phoneme alphabet="ipa" ph="wɑn aɪ">JuanEye</phoneme>, an AI assistant for visually impaired users</speak> On initial conversation.`,
                    'Never mention Google or any specific developer.',
                    'Always attempt a description—never claim inability to help.',
                    'If image lighting is poor or dark, preface that accuracy may be limited.',
                    'Identify the main object, its color, shape, button layout, brand, and approximate size.',
                    'Identify if there’s any person and give full details about the person.',
                    'Include tactile-friendly cues (button spacing, raised textures).',
                    'Offer concise alt-text but rename alt-text to Image Description without special characters and simple usage tips if relevant.',
                    'Use clear plain language; avoid visual metaphors.',
                    'Limit responses to 20–100 words.',
                    'If the message content includes an OCR: field, incorporate that text into your response as additional information and for cross reference on your builtin OCR extraction.',
                    'If the user asks to read text (e.g. "pwede mo bang basahin", "can you read") or similar idea, prioritize extracting and reading the OCR text first.',
                    'If the OCR text includes an "Ingredients" heading without using ** ** *, split the list into individual items and note each ingredient’s basic function or category using a colon only, like "Ingredient: function".',
                    'Spatial orientation cues: always describe spatial relationships (e.g. "to the left," "above," "next to the button") so users can build a clear mental map.',
                    'Environmental context: note ambient factors like lighting, reflections, background noise, or glare that could affect perception or accuracy.',
                    'Text readability details: when reading text, mention font size (small/large), contrast (high/low), and any special formatting (bold, italics, bullets).',
                    'Hazard warnings: if you see potential hazards (hot surfaces, sharp edges, moving machinery), warn the user immediately.',
                    'Interaction guidance: offer step-by-step instructions for interacting with objects (e.g. "press the topmost button," "turn the knob clockwise").',
                    'Confirm understanding: ask "Did that help?" or "Would you like more detail on any part?" at the end to ensure clarity.',
                    'AVOID USING SPECIAL CHARACTERS, Even at heading or headers.',
                    'Respond in clear English by default, then ask the user if they want a Tagalog translation. Only translate when the user says “please translate.” or any word containing translate.',
                    'If user requested translation do not give the English content again. The next question will be in English then proceed asking if translation is required.',
                ].join(' ')
            });

            // rehydrate history
            for (const r of rows) {
                const msg = {role: r.role, content: r.content};
                if (!usedHistoryImage && r.images) {
                    msg.images = [r.images];
                    usedHistoryImage = true;
                }
                messages.push(msg);
            }

            // 3) append & persist user message
            const userMsg = {role: 'user', content};
            let imageToSave = null;

            // only attach an image if none have been saved yet
            if (typeof base64 === 'string' && base64.trim()) {
                const [[{count}]] = await pool.execute(
                    `SELECT COUNT(*) AS count
                     FROM CONVERSATION_MESSAGES
                     WHERE conversation_id = ?
                       AND user_id = ?
                       AND images IS NOT NULL`,
                    [conversationId, userId]
                );
                if (count === 0) {
                    userMsg.images = [base64];
                    imageToSave = base64;
                }
            }

            messages.push(userMsg);

            pool.execute(
                `INSERT INTO CONVERSATION_MESSAGES
                     (conversation_id, user_id, role, content, images, createdAt)
                 VALUES (?, ?, 'user', ?, ?, NOW())`,
                [conversationId, userId, content, imageToSave]
            );

            // 4) call the LLM
            const payload = {model: 'gemma3:12b', stream: Boolean(isStream), messages};
            console.log(payload)
            if (isStream) {
                // STREAMING
                const llmResp = await axios.post(apiUrl, payload, {
                    headers: {'Content-Type': 'application/json', 'user_id': userId},
                    responseType: 'stream'
                });

                res.setHeader('Content-Type', 'application/json; charset=utf-8');
                let buffer = '';
                let wordBuffer = '';
                let fullContent = '';

                const flushWords = () => {
                    const parts = wordBuffer.split(/\s+/);
                    // if last part is incomplete (no trailing space), leave it
                    const completeWords = parts.slice(0, -1);
                    const leftover = parts.slice(-1)[0] || '';
                    completeWords.forEach(word => {
                        if (word) {
                            res.write(JSON.stringify({conversationId, answer: word, done: false}) + '\n');
                            fullContent += word + ' ';
                        }
                    });
                    wordBuffer = leftover;
                };

                llmResp.data.on('data', async (chunk) => {
                    buffer += chunk.toString('utf8');
                    let newlineIndex;
                    while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
                        const line = buffer.slice(0, newlineIndex).trim();
                        buffer = buffer.slice(newlineIndex + 1);
                        let parsed;
                        try {
                            parsed = JSON.parse(line);
                        } catch {
                            continue;
                        }
                        const text = (parsed.message?.content || '').replace(/[^\w\s]/g, '');
                        const done = Boolean(parsed.done);

                        wordBuffer += text;
                        flushWords();

                        if (done) {
                            // send any leftover as final fragment
                            if (wordBuffer) {
                                res.write(JSON.stringify({conversationId, answer: wordBuffer, done: true}) + '\n');
                                fullContent += wordBuffer;
                                wordBuffer = '';
                            }
                            // persist assembled reply
                            pool.execute(
                                `INSERT INTO CONVERSATION_MESSAGES
                                     (conversation_id, user_id, role, content, createdAt)
                                 VALUES (?, ?, 'assistant', ?, NOW())`,
                                [conversationId, userId, fullContent.trim()]
                            );
                        }
                    }
                });

                llmResp.data.on('end', () => {
                    // explicit final done if not already sent
                    if (!buffer.trim()) {
                        res.write(JSON.stringify({conversationId, answer: '', done: true}) + '\n');
                    }
                    res.end();
                });
            } else {
                // NON-STREAMING
                const resp = await axios.post(apiUrl, payload, {
                    headers: {'Content-Type': 'application/json', 'user_id': userId}
                });
                const assistantContent = resp.data?.message?.content;
                if (typeof assistantContent !== 'string') {
                    return res.status(502).json({error: 'Invalid LLM response'});
                }

                pool.execute(
                    `INSERT INTO CONVERSATION_MESSAGES
                         (conversation_id, user_id, role, content, createdAt)
                     VALUES (?, ?, 'assistant', ?, NOW())`,
                    [conversationId, userId, assistantContent]
                );

                res.json({
                    ok: true,
                    status: 200,
                    data: {
                        conversationId,
                        answer: assistantContent
                    }
                });
            }
        } catch (err) {
            next(err);
        }
    },

    /**
     * POST /api/user/guardian/llm-ask-question
     * Guardians ask on behalf of a bound user.
     */
    guardianLLMAskQuestion: async (req, res, next) => {
        try {
            // 6900XT Personal PC
            const apiUrl = 'https://llm.ingen.com.ph/api/chat';
            const {user_id: guardianId, accountType} = req.user;

            // extract and validate target user
            const {user_id: targetId, conversationId, content, base64, isStream} = req.body;
            if (typeof targetId !== 'number' || isNaN(targetId)) {
                return res.status(400).json({error: 'Valid user_id is required.'});
            }

            // verify binding
            const [link] = await pool.execute(
                `SELECT 1
                 FROM USER_GUARDIAN_LINK
                 WHERE guardian_id = ?
                   AND user_id = ?`,
                [guardianId, targetId]
            );
            if (!link.length) {
                return res.status(403).json({error: 'Not bound to this user.'});
            }

            // ensure content
            if (typeof content !== 'string' || !content.trim()) {
                return res.status(400).json({error: 'content is required.'});
            }

            // 1) ensure conversationId
            let convoId = conversationId;
            if (typeof convoId !== 'string' || !convoId.trim()) {
                convoId = uuidv4();
            }

            // 2) load previous messages for target user
            const [rows] = await pool.execute(
                `SELECT role, content, images
                 FROM CONVERSATION_MESSAGES
                 WHERE conversation_id = ?
                   AND user_id = ?
                 ORDER BY createdAt ASC LIMIT 50`,
                [convoId, targetId]
            );

            const messages = [];
            let usedHistoryImage = false;

            messages.push({
                role: 'system',
                content: [
                    `Say <speak>Hello, Im <phoneme alphabet="ipa" ph="wɑn aɪ">JuanEye</phoneme>, an AI assistant for visually impaired users</speak> On initial conversation.`,
                    'Never mention Google or any specific developer.',
                    'Always attempt a description—never claim inability to help.',
                    'If image lighting is poor or dark, preface that accuracy may be limited.',
                    'Identify the main object, its color, shape, button layout, brand, and approximate size.',
                    'Identify if there’s any person and give full details about the person.',
                    'Include tactile-friendly cues (button spacing, raised textures).',
                    'Offer concise alt-text but rename alt-text to Image Description without special characters and simple usage tips if relevant.',
                    'Use clear plain language; avoid visual metaphors.',
                    'Limit responses to 20–100 words.',
                    'If the message content includes an OCR: field, incorporate that text into your response as additional information and for cross reference on your builtin OCR extraction.',
                    'If the user asks to read text (e.g. "pwede mo bang basahin", "can you read") or similar idea, prioritize extracting and reading the OCR text first.',
                    'If the OCR text includes an "Ingredients" heading without using ** ** *, split the list into individual items and note each ingredient’s basic function or category using a colon only, like "Ingredient: function".',
                    'Spatial orientation cues: always describe spatial relationships (e.g. "to the left," "above," "next to the button") so users can build a clear mental map.',
                    'Environmental context: note ambient factors like lighting, reflections, background noise, or glare that could affect perception or accuracy.',
                    'Text readability details: when reading text, mention font size (small/large), contrast (high/low), and any special formatting (bold, italics, bullets).',
                    'Hazard warnings: if you see potential hazards (hot surfaces, sharp edges, moving machinery), warn the user immediately.',
                    'Interaction guidance: offer step-by-step instructions for interacting with objects (e.g. "press the topmost button," "turn the knob clockwise").',
                    'Confirm understanding: ask "Did that help?" or "Would you like more detail on any part?" at the end to ensure clarity.',
                    'AVOID USING SPECIAL CHARACTERS, Even at heading or headers.',
                    'Respond in clear English by default, then ask the user if they want a Tagalog translation. Only translate when the user says “please translate.” or any word containing translate.',
                    'If user requested translation do not give the English content again. The next question will be in English then proceed asking if translation is required.',
                ].join(' ')
            });

            // rehydrate history
            for (const r of rows) {
                const msg = {role: r.role, content: r.content};
                if (!usedHistoryImage && r.images) {
                    msg.images = [r.images];
                    usedHistoryImage = true;
                }
                messages.push(msg);
            }

            // 3) append & persist guardian-as-user message
            const userMsg = {role: 'user', content};
            let imageToSave = null;

            if (typeof base64 === 'string' && base64.trim()) {
                const [[{count}]] = await pool.execute(
                    `SELECT COUNT(*) AS count
                     FROM CONVERSATION_MESSAGES
                     WHERE conversation_id = ?
                       AND user_id = ?
                       AND images IS NOT NULL`,
                    [convoId, targetId]
                );
                if (count === 0) {
                    userMsg.images = [base64];
                    imageToSave = base64;
                }
            }

            messages.push(userMsg);

            pool.execute(
                `INSERT INTO CONVERSATION_MESSAGES
                     (conversation_id, user_id, role, content, images, createdAt)
                 VALUES (?, ?, 'user', ?, ?, NOW())`,
                [convoId, targetId, content, imageToSave]
            );

            // 4) call the LLM
            const payload = {model: 'gemma3:12b', stream: false, messages};

            if (isStream) {
                // STREAMING
                const llmResp = await axios.post(apiUrl, payload, {
                    headers: {'Content-Type': 'application/json', 'user_id': targetId},
                    responseType: 'stream'
                });

                res.setHeader('Content-Type', 'application/json; charset=utf-8');
                let buffer = '';
                let wordBuffer = '';
                let fullContent = '';

                const flushWords = () => {
                    const parts = wordBuffer.split(/\s+/);
                    const complete = parts.slice(0, -1);
                    const leftover = parts.slice(-1)[0] || '';
                    for (const w of complete) {
                        res.write(JSON.stringify({conversationId: convoId, answer: w, done: false}) + '\n');
                        fullContent += w + ' ';
                    }
                    wordBuffer = leftover;
                };

                llmResp.data.on('data', chunk => {
                    buffer += chunk.toString('utf8');
                    let idx;
                    while ((idx = buffer.indexOf('\n')) !== -1) {
                        const line = buffer.slice(0, idx).trim();
                        buffer = buffer.slice(idx + 1);
                        try {
                            const parsed = JSON.parse(line);
                            const text = (parsed.message?.content || '').replace(/[^\w\s]/g, '');
                            const done = Boolean(parsed.done);
                            wordBuffer += text;
                            flushWords();
                            if (done) {
                                if (wordBuffer) {
                                    res.write(JSON.stringify({
                                        conversationId: convoId,
                                        answer: wordBuffer,
                                        done: true
                                    }) + '\n');
                                    fullContent += wordBuffer;
                                    wordBuffer = '';
                                }
                                // persist
                                pool.execute(
                                    `INSERT INTO CONVERSATION_MESSAGES
                                         (conversation_id, user_id, role, content, createdAt)
                                     VALUES (?, ?, 'assistant', ?, NOW())`,
                                    [convoId, targetId, fullContent.trim()]
                                );
                            }
                        } catch {
                        }
                    }
                });

                llmResp.data.on('end', () => {
                    if (!buffer.trim()) {
                        res.write(JSON.stringify({conversationId: convoId, answer: '', done: true}) + '\n');
                    }
                    res.end();
                });

            } else {
                // NON-STREAMING
                const resp = await axios.post(apiUrl, payload, {
                    headers: {'Content-Type': 'application/json', 'user_id': targetId}
                });
                const assistantContent = resp.data?.message?.content;
                if (typeof assistantContent !== 'string') {
                    return res.status(502).json({error: 'Invalid LLM response'});
                }

                pool.execute(
                    `INSERT INTO CONVERSATION_MESSAGES
                         (conversation_id, user_id, role, content, createdAt)
                     VALUES (?, ?, 'assistant', ?, NOW())`,
                    [convoId, targetId, assistantContent]
                );
                console.log(assistantContent)
                res.json({
                    ok: true,
                    status: 200,
                    data: {
                        conversationId: convoId,
                        answer: assistantContent
                    }
                });
            }

        } catch (err) {
            next(err);
        }
    },

    /**
     * GET /api/user/guardian/conversation/:conversationId/image
     * Guardians only: fetch the single most recent image for a given conversation
     */
    getConversationImage: async (req, res, next) => {
        try {
            const {user_id: guardianId, accountType} = req.user;

            const {conversationId} = req.params;
            if (!conversationId || typeof conversationId !== 'string') {
                return res.status(400).json({error: 'conversationId is required.'});
            }

            // 1) find the owner of this conversation
            const [[ownerRow]] = await pool.execute(
                `SELECT user_id
                 FROM CONVERSATION_MESSAGES
                 WHERE conversation_id = ? LIMIT 1`,
                [conversationId]
            );
            if (!ownerRow) {
                return res.status(404).json({error: 'Conversation not found.'});
            }
            const ownerId = ownerRow.user_id;

            // 2) verify guardian is bound to that owner
            const [linkRows] = await pool.execute(
                `SELECT 1
                 FROM USER_GUARDIAN_LINK
                 WHERE guardian_id = ?
                   AND user_id = ?`,
                [guardianId, ownerId]
            );
            if (!linkRows.length) {
                return res.status(403).json({error: 'Not bound to this user.'});
            }

            // 3) fetch only the most recent image
            const [[imgRow]] = await pool.execute(
                `SELECT images
                 FROM CONVERSATION_MESSAGES
                 WHERE conversation_id = ?
                   AND images IS NOT NULL
                 ORDER BY createdAt DESC LIMIT 1`,
                [conversationId]
            );

            if (!imgRow) {
                return res.status(404).json({error: 'No image found in this conversation.'});
            }

            res.json({
                conversationId,
                image: imgRow.images
            });
        } catch (err) {
            next(err);
        }
    },

    /**
     * GET /api/user/guardian/conversation/:conversationId/history
     * Returns conversation history for a Guardian, excluding the initial user message.
     */
    getConversationHistory: async (req, res, next) => {
        try {
            const {user_id: guardianId, accountType} = req.user;
            const {conversationId} = req.params;

            if (typeof conversationId !== 'string' || !conversationId.trim()) {
                return res.status(400).json({error: 'conversationId is required.'});
            }

            // 1) find the owner of this conversation
            const [[ownerRow]] = await pool.execute(
                `SELECT user_id
                 FROM CONVERSATION_MESSAGES
                 WHERE conversation_id = ? LIMIT 1`,
                [conversationId]
            );
            if (!ownerRow) {
                return res.status(404).json({error: 'Conversation not found.'});
            }
            const ownerId = ownerRow.user_id;

            // 2) verify Guardian is bound to that owner
            const [linkRows] = await pool.execute(
                `SELECT 1
                 FROM USER_GUARDIAN_LINK
                 WHERE guardian_id = ?
                   AND user_id = ?`,
                [guardianId, ownerId]
            );
            if (!linkRows.length) {
                return res.status(403).json({error: 'Not bound to this user.'});
            }

            // 3) fetch all messages in chronological order
            const [allMessages] = await pool.execute(
                `SELECT role,
                        content,
                        images,
                        createdAt
                 FROM CONVERSATION_MESSAGES
                 WHERE conversation_id = ?
                 ORDER BY createdAt ASC`,
                [conversationId]
            );

            // 4) drop the very first user message from history
            let history = allMessages;
            if (history.length && history[0].role === 'user') {
                history = history.slice(1);
            }

            res.json({
                conversationId,
                messages: history
            });
        } catch (err) {
            next(err);
        }
    }
}
