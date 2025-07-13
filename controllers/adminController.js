// controllers/adminController.js

const pool = require('../db');
const bcrypt = require('bcryptjs');

/**
 * Helper to format a raw USERS row into the shape the UI expects:
 *   { user_id, email, userType, subscriptionType, scanCount, guardianModeAccess }
 */
function formatUserRow(row) {
    return {
        user_id: row.user_id,
        email: row.email,
        userType: row.accountType, // 'User' | 'Guardian' | 'Admin'
        subscriptionType: row.isPremiumUser ? 'Premium' : 'Free',
        scanCount: row.scanCount,
        guardianModeAccess: row.accountType === 'Guardian' ? 'Yes' : 'No'
    };
}

module.exports = {
    /**
     * POST /api/admin/users
     * Body: {
     *   email: string,
     *   password: string,
     *   accountType: 'User' | 'Guardian' | 'Admin',
     *   isPremiumUser: boolean,
     *   scanCount: number,
     *   phone?: string,
     *   deviceUuid?: string
     * }
     * Creates a new user in the USERS table. Password is hashed.
     * Returns the created user’s formatted row.
     */
    createUser: async (req, res, next) => {
        try {
            const {
                email,
                password,
                accountType,
                isPremiumUser,
                scanCount,
                phone = null,
                deviceUuid = null
            } = req.body;

            // Basic validation
            if (
                typeof email !== 'string' ||
                typeof password !== 'string' ||
                !['User', 'Guardian', 'Admin'].includes(accountType) ||
                typeof isPremiumUser !== 'boolean' ||
                typeof scanCount !== 'number'
            ) {
                return res.status(400).json({
                    error: 'Request body must include email(string), password(string), accountType(User|Guardian|Admin), isPremiumUser(boolean), scanCount(number). Phone and deviceUuid are optional.'
                });
            }

            // 1) Check if email already exists
            const [existingRows] = await pool.execute(
                `SELECT user_id FROM USERS WHERE email = ?`,
                [email]
            );
            if (existingRows.length > 0) {
                return res.status(409).json({ error: 'Email already in use.' });
            }

            // 2) Hash the password
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // 3) Insert into USERS
            const [insertResult] = await pool.execute(
                `INSERT INTO USERS
                 (email, password, accountType, isPremiumUser, scanCount, phone, deviceUuid, createdAt, updatedAt)
                 VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [email, hashedPassword, accountType, isPremiumUser, scanCount, phone, deviceUuid]
            );

            const newUserId = insertResult.insertId;

            // 4) Fetch the newly created row to return formatted
            const [rows] = await pool.execute(
                `SELECT user_id, email, accountType, isPremiumUser, scanCount
                 FROM USERS
                 WHERE user_id = ?`,
                [newUserId]
            );
            if (rows.length === 0) {
                return res.status(500).json({ error: 'Failed to retrieve newly created user.' });
            }
            const newRow = rows[0];
            const formatted = formatUserRow(newRow);

            return res.status(201).json({ user: formatted });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * GET /api/admin/dashboard
     * Returns:
     *   {
     *     onlineUsers: <count>,
     *     totalUsers: <count>,
     *     freeUsers: <count>,
     *     premiumUsers: <count>,
     *     newSignupsLast7Days: [
     *       { date: 'YYYY-MM-DD', count: <number> },
     *       ...
     *     ]
     *   }
     */
    getDashboardStats: async (req, res, next) => {
        try {
            // 1) Count "online" users based on recent activity in scans tables
            //    Any user with ≥1 entry in OBJECT_SCANS, OCR_SCANS, or LLM_SCANS
            //    in the past 1 hour is considered online.
            const scanWindow = '1 HOUR';
            const [onlineRows] = await pool.execute(
                `SELECT COUNT(DISTINCT user_id) AS cnt FROM (
                                                                SELECT user_id
                                                                FROM OBJECT_SCANS
                                                                WHERE createdAt >= DATE_SUB(NOW(), INTERVAL ${scanWindow})
                                                                UNION
                                                                SELECT user_id
                                                                FROM OCR_SCANS
                                                                WHERE createdAt >= DATE_SUB(NOW(), INTERVAL ${scanWindow})
                                                                UNION
                                                                SELECT user_id
                                                                FROM CONVERSATION_MESSAGES
                                                                WHERE createdAt >= DATE_SUB(NOW(), INTERVAL ${scanWindow})
                                                            ) AS recent_activity`
            );
            const onlineUsers = onlineRows[0].cnt;

            // 2) Total users
            const [totalRows] = await pool.execute(
                `SELECT COUNT(*) AS cnt FROM USERS`
            );
            const totalUsers = totalRows[0].cnt;

            // 3) Free users
            const [freeRows] = await pool.execute(
                `SELECT COUNT(*) AS cnt
                 FROM USERS
                 WHERE isPremiumUser = FALSE`
            );
            const freeUsers = freeRows[0].cnt;

            // 4) Premium users
            const [premiumRows] = await pool.execute(
                `SELECT COUNT(*) AS cnt
                 FROM USERS
                 WHERE isPremiumUser = TRUE`
            );
            const premiumUsers = premiumRows[0].cnt;

            // 5) New signups last 7 days, formatted 'YYYY-MM-DD'
            const [signupRows] = await pool.execute(
                `SELECT
               DATE_FORMAT(createdAt, '%Y-%m-%d') AS date,
               COUNT(*)                    AS count
             FROM USERS
            WHERE createdAt >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
            GROUP BY DATE_FORMAT(createdAt, '%Y-%m-%d')
            ORDER BY DATE_FORMAT(createdAt, '%Y-%m-%d')`
            );

            return res.json({
                onlineUsers,
                totalUsers,
                freeUsers,
                premiumUsers,
                newSignupsLast7Days: signupRows
            });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * GET /api/admin/users
     * Query: ?page=<number>&limit=<number>&search=<string>
     * Returns:
     *   { total: <number>, users: [ formattedUser, ... ] }
     */
    listUsers: async (req, res, next) => {
        try {
            let { page, limit, search } = req.query;
            page = parseInt(page) || 1;
            limit = parseInt(limit) || 10;
            const offset = (page - 1) * limit;

            let countSql = 'SELECT COUNT(*) AS cnt FROM USERS';
            let dataSql =
                `SELECT user_id, email, accountType, isPremiumUser, scanCount
         FROM USERS`;
            const countParams = [];
            const dataParams = [];

            if (search && search.trim()) {
                const wildcard = `%${search.trim()}%`;
                countSql += ' WHERE email LIKE ?';
                dataSql += ' WHERE email LIKE ?';
                countParams.push(wildcard);
                dataParams.push(wildcard);
            }

            // 1) Execute count
            const [countRows] = await pool.execute(countSql, countParams);
            const total = countRows[0].cnt;

            // 2) Execute data query with inlined LIMIT/OFFSET
            dataSql += ` ORDER BY user_id DESC LIMIT ${limit} OFFSET ${offset}`;
            const [rows] = await pool.execute(dataSql, dataParams);

            // 3) Format
            const users = rows.map(formatUserRow);
            return res.json({ total, users });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * GET /api/admin/users/:userId
     * Returns a single user's detail.
     */
    getUserById: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId);
            if (isNaN(userId)) {
                return res.status(400).json({ error: 'Invalid userId parameter' });
            }
            const [rows] = await pool.execute(
                `SELECT user_id, email, accountType, isPremiumUser, scanCount, phone, deviceUuid, createdAt, updatedAt
         FROM USERS
         WHERE user_id = ?`,
                [userId]
            );
            if (rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            const row = rows[0];
            const detail = {
                user_id: row.user_id,
                email: row.email,
                userType: row.accountType,
                subscriptionType: row.isPremiumUser ? 'Premium' : 'Free',
                scanCount: row.scanCount,
                guardianModeAccess: row.accountType === 'Guardian' ? 'Yes' : 'No',
                phone: row.phone,
                deviceUuid: row.deviceUuid,
                createdAt: row.createdAt,
                updatedAt: row.updatedAt
            };
            return res.json(detail);
        } catch (err) {
            return next(err);
        }
    },

    /**
     * PUT /api/admin/users/:userId
     * Body: { email, accountType, isPremiumUser, scanCount, phone?, deviceUuid? }
     * Updates those fields on the user.
     */
    updateUser: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId);
            if (isNaN(userId)) {
                return res.status(400).json({ error: 'Invalid userId parameter' });
            }

            const { email, accountType, isPremiumUser, scanCount, phone = null, deviceUuid = null } = req.body;
            if (
                typeof email !== 'string' ||
                !['User', 'Guardian', 'Admin'].includes(accountType) ||
                typeof isPremiumUser !== 'boolean' ||
                typeof scanCount !== 'number'
            ) {
                return res.status(400).json({
                    error: 'Request must include email(string), accountType(User|Guardian|Admin), isPremiumUser(boolean), scanCount(number).'
                });
            }

            await pool.execute(
                `UPDATE USERS
         SET email         = ?,
             accountType   = ?,
             isPremiumUser = ?,
             scanCount     = ?,
             phone         = ?,
             deviceUuid    = ?,
             updatedAt     = NOW()
         WHERE user_id = ?`,
                [email, accountType, isPremiumUser, scanCount, phone, deviceUuid, userId]
            );

            return res.json({ message: 'User updated successfully.' });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * DELETE /api/admin/users/:userId
     * Deletes a user and all related data.
     */
    deleteUser: async (req, res, next) => {
        const conn = await pool.getConnection();
        try {
            const userId = parseInt(req.params.userId);
            if (isNaN(userId)) {
                conn.release();
                return res.status(400).json({ error: 'Invalid userId parameter' });
            }

            await conn.beginTransaction();

            // a) USER_GUARDIAN_LINK
            await conn.execute(
                `DELETE FROM USER_GUARDIAN_LINK
                 WHERE user_id = ? OR guardian_id = ?`,
                [userId, userId]
            );

            // b) OTPS
            await conn.execute(
                `DELETE FROM OTPS WHERE user_id = ?`,
                [userId]
            );

            await conn.execute(
                `DELETE FROM VOICE_MESSAGES WHERE user_id = ?`,
                [userId]
            );

            // c) OBJECT_SCANS
            await conn.execute(
                `DELETE FROM OBJECT_SCANS WHERE user_id = ?`,
                [userId]
            );

            // d) OCR_SCANS
            await conn.execute(
                `DELETE FROM OCR_SCANS WHERE user_id = ?`,
                [userId]
            );

            // e) PAYMENTS
            await conn.execute(
                `DELETE FROM PAYMENTS WHERE user_id = ?`,
                [userId]
            );

            // f) AUDIT_TRAIL
            await conn.execute(
                `DELETE FROM AUDIT_TRAIL WHERE changed_by = ?`,
                [userId]
            );


            const [delResult] = await conn.execute(
                `DELETE FROM USERS WHERE user_id = ?`,
                [userId]
            );
            if (delResult.affectedRows === 0) {
                await conn.rollback();
                conn.release();
                return res.status(404).json({ error: 'User not found' });
            }

            await conn.commit();
            conn.release();
            return res.json({ message: 'User and related data deleted successfully.' });
        } catch (err) {
            await conn.rollback();
            conn.release();
            return next(err);
        }
    },

    /**
     * GET /api/admin/users/:userId/scans
     * Returns both OBJECT_SCANS and OCR_SCANS for that user, sorted by createdAt DESC.
     */
    getUserScans: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId);
            if (isNaN(userId)) {
                return res.status(400).json({ error: 'Invalid userId parameter' });
            }

            // 1) fetch object & OCR scans
            const [scanRows] = await pool.execute(
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
                [userId, userId]
            );

            // 2) fetch LLM conversation summaries (first user message, first assistant reply, first image)
            const convoSql = `
                SELECT
                    ucm.conversation_id             AS conversationId,
                    'LLM'                           AS type,
                    ucm.createdAt                   AS createdAt,
                    ucm.content                     AS first_user_message,
                    (
                        SELECT cm.content
                        FROM CONVERSATION_MESSAGES cm
                        WHERE cm.conversation_id = ucm.conversation_id
                          AND cm.role = 'assistant'
                          AND cm.createdAt > ucm.createdAt
                        ORDER BY cm.createdAt ASC
                                                       LIMIT 1
                    )                               AS first_assistant_message,
            (
              SELECT cm2.images
              FROM CONVERSATION_MESSAGES cm2
              WHERE cm2.conversation_id = ucm.conversation_id
                AND cm2.images IS NOT NULL
              ORDER BY cm2.createdAt ASC
              LIMIT 1
            )                               AS images
                FROM (
                    SELECT conversation_id, MIN(createdAt) AS firstAt
                    FROM CONVERSATION_MESSAGES
                    WHERE user_id = ?
                    AND role = 'user'
                    GROUP BY conversation_id
                    ) t
                    JOIN CONVERSATION_MESSAGES ucm
                ON ucm.conversation_id = t.conversation_id
                    AND ucm.createdAt       = t.firstAt
                    AND ucm.role            = 'user'
                ORDER BY ucm.createdAt DESC
            `;
            const [convoRows] = await pool.execute(convoSql, [userId]);

            // 3) merge & sort everything by createdAt DESC
            const combined = [...scanRows, ...convoRows].sort(
                (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
            );

            return res.json(combined);
        } catch (err) {
            return next(err);
        }
    },

    /**
     * PUT /api/admin/scans/:scanId
     * Body: { type, name, text }
     */
    updateScan: async (req, res, next) => {
        try {
            const scanId = parseInt(req.params.scanId);
            if (isNaN(scanId)) {
                return res.status(400).json({ error: 'Invalid scanId parameter' });
            }

            const { type, name, text } = req.body;
            if (!['Object', 'Text'].includes(type) || typeof name !== 'string' || typeof text !== 'string') {
                return res.status(400).json({
                    error: "Request body must include type('Object'|'Text'), name(string), text(string)."
                });
            }

            if (type === 'Object') {
                const [result] = await pool.execute(
                    `UPDATE OBJECT_SCANS
           SET recognizedObjects = ?, text = ?, updatedAt = NOW()
           WHERE scan_id = ?`,
                    [name, text, scanId]
                );
                if (result.affectedRows === 0) {
                    return res.status(404).json({ error: 'Object scan not found' });
                }
            } else {
                const [result] = await pool.execute(
                    `UPDATE OCR_SCANS
           SET recognizedText = ?, text = ?, updatedAt = NOW()
           WHERE ocr_id = ?`,
                    [name, text, scanId]
                );
                if (result.affectedRows === 0) {
                    return res.status(404).json({ error: 'OCR scan not found' });
                }
            }

            return res.json({ message: 'Scan updated successfully.' });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * DELETE /api/admin/scans/:scanId
     * Tries to delete from OCR_SCANS first, then OBJECT_SCANS.
     */
    deleteScan: async (req, res, next) => {
        try {
            const scanId = parseInt(req.params.scanId);
            if (isNaN(scanId)) {
                return res.status(400).json({ error: 'Invalid scanId parameter' });
            }

            // 1) Try OCR_SCANS
            const [ocrDel] = await pool.execute(
                `DELETE FROM OCR_SCANS WHERE ocr_id = ?`,
                [scanId]
            );
            if (ocrDel.affectedRows > 0) {
                return res.json({ message: 'OCR scan deleted successfully.' });
            }

            // 2) Then OBJECT_SCANS
            const [objDel] = await pool.execute(
                `DELETE FROM OBJECT_SCANS WHERE scan_id = ?`,
                [scanId]
            );
            if (objDel.affectedRows > 0) {
                return res.json({ message: 'Object scan deleted successfully.' });
            }

            return res.status(404).json({ error: 'Scan not found in either table' });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * GET /api/admin/report?date=YYYY-MM-DD
     * Returns all users whose createdAt date exactly matches.
     */
    generateReport: async (req, res, next) => {
        try {
            const { date } = req.query;
            if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
                return res.status(400).json({ error: 'Query parameter "date" must be provided as YYYY-MM-DD.' });
            }

            const [rows] = await pool.execute(
                `SELECT user_id, email, accountType, isPremiumUser, scanCount
                 FROM USERS
                 WHERE DATE_FORMAT(createdAt, '%Y-%m-%d') = ?`,
                [date]
            );

            const users = rows.map(formatUserRow);
            return res.json({ date, users });
        } catch (err) {
            return next(err);
        }
    }
};
