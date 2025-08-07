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
        guardianModeAccess: row.accountType === 'Guardian' ? 'Yes' : 'No',
        premium_expiration: row.premiumExpiration
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
            // All queries are now in a transaction to ensure data consistency
            const conn = await pool.getConnection();
            await conn.beginTransaction();

            try {
                // 1) Recently logged in users
                const scanWindow = '1 HOUR';
                const [onlineRows] = await conn.execute(
                    `SELECT COUNT(DISTINCT user_id) AS cnt
                     FROM (
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
                const recentlyLoggedInUsers = onlineRows[0].cnt;

                // 2) User stats
                const [statRows] = await conn.execute(`
                    SELECT
                        COUNT(*)                                     AS total,
                        SUM(CASE WHEN isPremiumUser = true THEN 1 ELSE 0 END)  AS premium,
                        SUM(CASE WHEN accountType = 'Guardian' THEN 1 ELSE 0 END) AS guardian,
                        SUM(CASE WHEN isPremiumUser = false AND accountType != 'Guardian' THEN 1 ELSE 0 END) AS free
                    FROM USERS
                    WHERE accountType != 'Admin'
                `);
                const {
                    total,
                    premium,
                    guardian,
                    free
                } = statRows[0];


                // 3) New signups in the last 7 days
                const [signupRows] = await conn.execute(`
                    SELECT DATE_FORMAT(createdAt, '%Y-%m-%d') AS date,
                           COUNT(*)                           AS count
                    FROM USERS
                    WHERE createdAt >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
                    GROUP BY date
                    ORDER BY date
                `);

                // 4) Top 10 most recent users for the table view
                const [userRows] = await conn.execute(`
                    SELECT user_id, email, accountType, isPremiumUser, scanCount
                    FROM USERS
                    WHERE accountType != 'Admin'
                    ORDER BY createdAt DESC
                    LIMIT 10
                `);
                const recentUsers = userRows.map(formatUserRow);

                await conn.commit();
                conn.release();

                return res.json({
                    recentlyLoggedInUsers: recentlyLoggedInUsers,
                    userStats: {
                        total: parseInt(total, 10) || 0,
                        premium: parseInt(premium, 10) || 0,
                        guardian: parseInt(guardian, 10) || 0,
                        free: parseInt(free, 10) || 0,
                    },
                    newSignupsLast7Days: signupRows,
                    recentUsers: recentUsers,
                });

            } catch (err) {
                await conn.rollback();
                conn.release();
                return next(err)
            }
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
                `SELECT user_id, email, accountType, isPremiumUser, scanCount, premiumExpiration
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
     * GET /api/admin/users/:userId/guardians
     * Returns all guardians currently bound to the specified user.
     */
    getUserGuardians: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId, 10);
            if (isNaN(userId)) {
                return res.status(400).json({ error: 'Invalid userId parameter' });
            }
            // Fetch guardian bindings
            const [rows] = await pool.execute(
                `SELECT 
                    u.user_id      AS guardian_id,
                    u.email        AS guardian_email
                 FROM USER_GUARDIAN_LINK ugl
                 JOIN USERS u
                   ON u.user_id = ugl.guardian_id
                 WHERE ugl.user_id = ?`,
                [userId]
            );
            return res.json({ guardians: rows });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * POST /api/admin/users/:userId/guardians
     * Body: { guardianId: number }
     * Binds a guardian account to the specified user account.
     */
    bindGuardian: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId, 10);
            const guardianId = parseInt(req.body.guardianId, 10);

            if (isNaN(userId) || isNaN(guardianId)) {
                return res.status(400).json({ error: 'userId and guardianId must be numbers.' });
            }
            if (userId === guardianId) {
                return res.status(400).json({ error: 'Cannot bind a user as their own guardian.' });
            }

            // Verify user is of type 'User'
            const [userRows] = await pool.execute(
                `SELECT accountType FROM USERS WHERE user_id = ?`,
                [userId]
            );
            if (!userRows.length || userRows[0].accountType !== 'User') {
                return res.status(400).json({ error: 'Target user must have accountType "User".' });
            }

            // Verify guardian is of type 'Guardian'
            const [guardRows] = await pool.execute(
                `SELECT accountType FROM USERS WHERE user_id = ?`,
                [guardianId]
            );
            if (!guardRows.length || guardRows[0].accountType !== 'Guardian') {
                return res.status(400).json({ error: 'guardianId must refer to a user with accountType "Guardian".' });
            }

            // Insert binding (ignore duplicates)
            await pool.execute(
                `INSERT IGNORE INTO USER_GUARDIAN_LINK (user_id, guardian_id)
                 VALUES (?, ?)`,
                [userId, guardianId]
            );

            return res.status(201).json({ message: 'Guardian bound to user successfully.' });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * DELETE /api/admin/users/:userId/guardians/:guardianId
     * Unbinds (removes) a guardian from the specified user.
     */
    unbindGuardian: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId, 10);
            const guardianId = parseInt(req.params.guardianId, 10);

            if (isNaN(userId) || isNaN(guardianId)) {
                return res.status(400).json({ error: 'userId and guardianId must be numbers.' });
            }

            const [result] = await pool.execute(
                `DELETE FROM USER_GUARDIAN_LINK
                 WHERE user_id = ? AND guardian_id = ?`,
                [userId, guardianId]
            );
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'No such guardian binding found.' });
            }

            return res.json({ message: 'Guardian unbound from user successfully.' });
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

            // Prevent admin from deleting their own account
            if (req.user && req.user.user_id === userId) {
                conn.release();
                return res.status(403).json({ error: 'Admins cannot delete their own account.' });
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

            // 2) fetch LLM conversation summaries (first user message, first assistant reply)
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
                    )                               AS first_assistant_message
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

            // 3) merge & sort everything by createdAt DESC including LLM
            const combined = [...scanRows, ...convoRows].sort(
                (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
            );

            return res.json(combined);
        } catch (err) {
            return next(err);
        }
    },

    /**
     * GET /api/admin/scans/:conversationId/images
     * Returns the first base64-encoded image for that conversation.
     */
    getConversationImages: async (req, res, next) => {
        try {
            const conversationId = req.params.conversationId;
            if (!conversationId) {
                return res.status(400).json({ error: 'Invalid conversationId parameter' });
            }

            const [rows] = await pool.execute(
                `SELECT
                 images AS images
             FROM CONVERSATION_MESSAGES
             WHERE conversation_id = ?
               AND images IS NOT NULL
             ORDER BY createdAt ASC
             LIMIT 1`,
                [conversationId]
            );

            if (!rows.length) {
                return res.status(404).json({ error: 'No images found for this conversation.' });
            }

            return res.json({ images: rows[0].images });
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
     * Tries to delete from OCR_SCANS first, then OBJECT_SCANS,
     * or if :scanId is a conversationId UUID, deletes all messages in that conversation.
     */
    deleteScan: async (req, res, next) => {
        try {
            const scanIdParam = req.params.scanId;

            const isUuid = /^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}$/.test(scanIdParam);
            if (isUuid) {
                const [msgDel] = await pool.execute(
                    `DELETE FROM CONVERSATION_MESSAGES WHERE conversation_id = ?`,
                    [scanIdParam]
                );
                if (msgDel.affectedRows > 0) {
                    return res.json({ message: 'LLM conversation deleted successfully.' });
                } else {
                    return res.status(404).json({ error: 'Conversation not found.' });
                }
            }

            // otherwise treat as numeric scanId
            const scanId = parseInt(scanIdParam, 10);
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
    },

    /**
     * GET /api/admin/conversations/:conversationId/history
     * Returns all conversation messages for the given conversationId,
     * excluding messages that include images.
     */
    getConversationHistory: async (req, res, next) => {
        try {
            const conversationId = req.params.conversationId;
            if (typeof conversationId !== 'string' || !conversationId.trim()) {
                return res.status(400).json({ error: 'Invalid conversationId parameter.' });
            }

            const [[exists]] = await pool.execute(
                `SELECT conversation_id
                   FROM CONVERSATION_MESSAGES
                  WHERE conversation_id = ?
                  LIMIT 1`,
                [conversationId]
            );
            if (!exists) {
                return res.status(404).json({ error: 'Conversation not found.' });
            }

            const [rows] = await pool.execute(
                `SELECT role,
                        content,
                        createdAt
                   FROM CONVERSATION_MESSAGES
                  WHERE conversation_id = ?
                    AND images IS NULL
                  ORDER BY createdAt ASC`,
                [conversationId]
            );

            return res.json({ conversationId, messages: rows });
        } catch (err) {
            return next(err);
        }
    },

    getAuditTrail: async (req, res, next) => {
        try {
            const { startDate, endDate, search } = req.query;

            if (!startDate || !endDate) {
                // Fetch all records if no date range is provided.
                const [rows] = await pool.execute(`
                    SELECT
                        a.audit_id,
                        a.changedAt,
                        a.changed_by,
                        u.email as user_email,
                        a.action,
                        a.status,
                        a.ip_address,
                        a.user_agent,
                        a.request_body
                    FROM CSB.AUDIT_TRAIL a
                    LEFT JOIN CSB.USERS u ON a.changed_by = u.user_id
                    ORDER BY a.changedAt DESC
                `);
                const processedRows = await Promise.all(rows.map(async (log) => {
                    let email = log.user_email;
                    if (!email && log.request_body) {
                        try {
                            const body = JSON.parse(log.request_body);
                            if (body && body.email) {
                                const [userRows] = await pool.execute('SELECT email FROM USERS WHERE email = ?', [body.email]);
                                if (userRows.length > 0) {
                                    email = userRows[0].email;
                                } else {
                                    email = body.email;
                                }
                            }
                        } catch (e) {
                            // Not a valid JSON, ignore
                        }
                    }
                    if (email) {
                        log.changed_by = email;
                    } else if (log.changed_by) {
                        log.changed_by = `User ID: ${log.changed_by}`;
                    } else {
                        log.changed_by = 'System/Unknown';
                    }
                    delete log.user_email;
                    return log;
                }));
                return res.json(processedRows);
            }

            const start = new Date(startDate);
            start.setHours(0, 0, 0, 0);

            const end = new Date(endDate);
            end.setHours(23, 59, 59, 999);

            let query = `
                SELECT
                    a.audit_id,
                    a.changedAt,
                    a.changed_by,
                    u.email as user_email,
                    a.action,
                    a.status,
                    a.ip_address,
                    a.user_agent,
                    a.request_body
                FROM CSB.AUDIT_TRAIL a
                LEFT JOIN CSB.USERS u ON a.changed_by = u.user_id
                WHERE a.changedAt >= ? AND a.changedAt <= ?
            `;
            const params = [start, end];

            if (search) {
                query += ` AND (u.email LIKE ? OR a.action LIKE ? OR a.ip_address LIKE ?)`;
                const searchTerm = `%${search}%`;
                params.push(searchTerm, searchTerm, searchTerm);
            }

            query += ` ORDER BY a.changedAt DESC`;

            const [rows] = await pool.execute(query, params);

            const processedRows = await Promise.all(rows.map(async (log) => {
                let email = log.user_email;
                if (!email && log.request_body) {
                    try {
                        const body = JSON.parse(log.request_body);
                        if (body && body.email) {
                            const [userRows] = await pool.execute('SELECT email FROM USERS WHERE email = ?', [body.email]);
                            if (userRows.length > 0) {
                                email = userRows[0].email;
                            } else {
                                email = body.email;
                            }
                        }
                    } catch (e) {
                        // Not a valid JSON, ignore
                    }
                }
                if (email) {
                    log.changed_by = email;
                } else if (log.changed_by) {
                    log.changed_by = `User ID: ${log.changed_by}`;
                } else {
                    log.changed_by = 'System/Unknown';
                }
                delete log.user_email;
                return log;
            }));
            res.json(processedRows);
        } catch (err) {
            next(err);
        }
    },


    listGuardians: async (req, res, next) => {
        try {
            const [rows] = await pool.execute(
                `SELECT user_id, email FROM USERS WHERE accountType = 'Guardian'`
            );
            res.json(rows);
        } catch (err) {
            next(err);
        }
    },

    getGuardianBoundUsers: async (req, res, next) => {
        try {
            const guardianId = parseInt(req.params.guardianId, 10);
            if (isNaN(guardianId)) {
                return res.status(400).json({ error: 'Invalid guardianId parameter' });
            }

            const [rows] = await pool.execute(
                `SELECT u.user_id, u.email
                 FROM USER_GUARDIAN_LINK ugl
                 JOIN USERS u ON u.user_id = ugl.user_id
                 WHERE ugl.guardian_id = ?`,
                [guardianId]
            );
            res.json(rows);
        } catch (err) {
            next(err);
        }
    },

    getUserActivity: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId, 10);
            if (isNaN(userId)) {
                return res.status(400).json({ error: 'Invalid userId parameter' });
            }

            const [rows] = await pool.execute(
                `SELECT action, changedAt, status
                 FROM AUDIT_TRAIL
                 WHERE changed_by = ?
                 ORDER BY changedAt DESC`,
                [userId]
            );
            res.json(rows);
        } catch (err) {
            next(err);
        }
    },
makeUserPremium: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId, 10);
            if (isNaN(userId)) {
                return res.status(400).json({ error: 'Invalid userId parameter' });
            }

            // Set premium status and a 1-year expiration date
            const expirationDate = new Date();
            expirationDate.setMonth(expirationDate.getMonth() + 1);

            const [result] = await pool.execute(
                `UPDATE USERS
                 SET isPremiumUser = ?, premiumExpiration = ?, updatedAt = NOW()
                 WHERE user_id = ?`,
                [1, expirationDate, userId]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            res.json({ message: 'User successfully upgraded to premium.' });
        } catch (err) {
            next(err);
        }
    },

    removeUserPremium: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId, 10);
            if (isNaN(userId)) {
                return res.status(400).json({ error: 'Invalid userId parameter' });
            }

            // Revoke premium status
            const [result] = await pool.execute(
                `UPDATE USERS
                 SET isPremiumUser = ?, premiumExpiration = NULL, updatedAt = NOW()
                 WHERE user_id = ?`,
                [0, userId]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            res.json({ message: 'Premium status successfully revoked.' });
        } catch (err) {
            next(err);
        }
    },

    getUserTransactions: async (req, res) => {
        try {
            const { userId } = req.params;
            const [transactions] = await pool.execute(
                'SELECT * FROM PAYMENTS WHERE user_id = ?',
                [userId]
            );
            return res.status(200).json(transactions);
        } catch (error) {
            return res.status(500).json({ message: 'Error fetching user transactions' });
        }
    },
};
