// controllers/adminController.js

const pool = require('../db');

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
     * GET /api/admin/dashboard
     * Returns:
     *   {
     *     onlineUsers: <count>,
     *     totalUsers: <count>,
     *     freeUsers: <count>,
     *     premiumUsers: <count>,
     *     newSignupsLast7Days: [
     *       { date: '2025-03-01', count: 7 },
     *       { date: '2025-03-02', count: 9 },
     *       ...
     *     ]
     *   }
     *
     * We use DATE_FORMAT(createdAt, '%Y-%m-%d') so the “date” field is always 'YYYY-MM-DD'.
     */
    getDashboardStats: async (req, res, next) => {
        try {
            // 1) Count users with a non-null deviceUuid (i.e., “online”)
            const [onlineRows] = await pool.execute(
                `SELECT COUNT(*) AS cnt
                 FROM USERS
                 WHERE deviceUuid IS NOT NULL`
            );
            const onlineUsers = onlineRows[0].cnt;

            // 2) Total users
            const [totalRows] = await pool.execute(
                `SELECT COUNT(*) AS cnt
                 FROM USERS`
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

            // 5) New signups for each of the last 7 days (including today).
            //    We format the date as 'YYYY-MM-DD' explicitly.
            const [signupRows] = await pool.execute(
                `SELECT
                     DATE_FORMAT(createdAt, '%Y-%m-%d') AS date,
           COUNT(*) AS count
                 FROM USERS
                 WHERE createdAt >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
                 GROUP BY DATE_FORMAT(createdAt, '%Y-%m-%d')
                 ORDER BY DATE_FORMAT(createdAt, '%Y-%m-%d')`
            );
            // signupRows example: [ { date: '2025-03-01', count: 7 }, ... ]

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
     * Query parameters:
     *   - page (default=1)
     *   - limit (default=10)
     *   - search (optional; filters by email substring)
     *
     * Response:
     *   {
     *     total: <total matching rows>,
     *     users: [
     *       { user_id, email, userType, subscriptionType, scanCount, guardianModeAccess },
     *       ...
     *     ]
     *   }
     *
     * NOTE: We inline LIMIT and OFFSET into the SQL string (as integers). Any 'search'
     *       filter is still passed as a placeholder to prevent SQL injection.
     */
    listUsers: async (req, res, next) => {
        try {
            let { page, limit, search } = req.query;
            page = parseInt(page) || 1;
            limit = parseInt(limit) || 10;
            const offset = (page - 1) * limit;

            // Build base SQL for counting and for data listing
            let countSql = 'SELECT COUNT(*) AS cnt FROM USERS';
            let dataSql =
                `SELECT user_id, email, accountType, isPremiumUser, scanCount
                 FROM USERS`;
            const countParams = [];
            const dataParams = [];

            // If a search term is provided, filter by email LIKE '%search%'
            if (search && search.trim()) {
                const searchWildcard = `%${search.trim()}%`;
                countSql += ' WHERE email LIKE ?';
                dataSql += ' WHERE email LIKE ?';
                countParams.push(searchWildcard);
                dataParams.push(searchWildcard);
            }

            // 1) Execute the COUNT query first (no LIMIT/OFFSET here)
            const [countRows] = await pool.execute(countSql, countParams);
            const total = countRows[0].cnt;

            // 2) Append ORDER, then inline LIMIT and OFFSET (now that 'limit'/'offset' are numeric)
            dataSql += ` ORDER BY user_id DESC LIMIT ${limit} OFFSET ${offset}`;
            // No need to push limit/offset into dataParams; they are inlined safely

            const [rows] = await pool.execute(dataSql, dataParams);

            // 3) Map each row into the shape the frontend expects
            const users = rows.map(formatUserRow);

            return res.json({ total, users });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * GET /api/admin/users/:userId
     * Returns exactly one user’s detail (same fields as listUsers, plus all raw columns if needed).
     */
    getUserById: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId);
            if (isNaN(userId)) {
                return res.status(400).json({ error: 'Invalid userId parameter' });
            }

            const [rows] = await pool.execute(
                `SELECT user_id, email, accountType, isPremiumUser, scanCount, deviceUuid, phone, createdAt, updatedAt
                 FROM USERS
                 WHERE user_id = ?`,
                [userId]
            );
            if (rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            const row = rows[0];
            const userDetail = {
                user_id: row.user_id,
                email: row.email,
                userType: row.accountType,
                subscriptionType: row.isPremiumUser ? 'Premium' : 'Free',
                scanCount: row.scanCount,
                guardianModeAccess: row.accountType === 'Guardian' ? 'Yes' : 'No',
                deviceUuid: row.deviceUuid,
                phone: row.phone,
                createdAt: row.createdAt,
                updatedAt: row.updatedAt
            };

            return res.json(userDetail);
        } catch (err) {
            return next(err);
        }
    },

    /**
     * PUT /api/admin/users/:userId
     * Body: { email, accountType, isPremiumUser, scanCount }
     * Updates exactly those fields on the USERS table.
     */
    updateUser: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId);
            if (isNaN(userId)) {
                return res.status(400).json({ error: 'Invalid userId parameter' });
            }

            const { email, accountType, isPremiumUser, scanCount } = req.body;
            // Basic validation
            if (
                typeof email !== 'string' ||
                !['User', 'Guardian', 'Admin'].includes(accountType) ||
                typeof isPremiumUser !== 'boolean' ||
                typeof scanCount !== 'number'
            ) {
                return res.status(400).json({
                    error:
                        'Request body must include email (string), accountType (User|Guardian|Admin), isPremiumUser (boolean), scanCount (number).'
                });
            }

            await pool.execute(
                `UPDATE USERS
                 SET email         = ?,
                     accountType   = ?,
                     isPremiumUser = ?,
                     scanCount     = ?,
                     updatedAt     = NOW()
                 WHERE user_id = ?`,
                [email, accountType, isPremiumUser, scanCount, userId]
            );

            return res.json({ message: 'User updated successfully.' });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * DELETE /api/admin/users/:userId
     * Deletes a user and all of their related rows in other tables:
     *   - USER_GUARDIAN_LINK (both user_id and guardian_id)
     *   - OTPS
     *   - OBJECT_SCANS
     *   - OCR_SCANS
     *   - PAYMENTS
     *   - AUDIT_TRAIL
     *   - VOICE_MESSAGES
     *   - Then the USERS row itself
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

            // a) Delete from USER_GUARDIAN_LINK
            await conn.execute(
                `DELETE FROM USER_GUARDIAN_LINK
                 WHERE user_id = ? OR guardian_id = ?`,
                [userId, userId]
            );

            // b) Delete from OTPS
            await conn.execute(
                `DELETE FROM OTPS
                 WHERE user_id = ?`,
                [userId]
            );

            // c) Delete from OBJECT_SCANS
            await conn.execute(
                `DELETE FROM OBJECT_SCANS
                 WHERE user_id = ?`,
                [userId]
            );

            // d) Delete from OCR_SCANS
            await conn.execute(
                `DELETE FROM OCR_SCANS
                 WHERE user_id = ?`,
                [userId]
            );

            // e) Delete from PAYMENTS
            await conn.execute(
                `DELETE FROM PAYMENTS
                 WHERE user_id = ?`,
                [userId]
            );

            // f) Delete from AUDIT_TRAIL
            await conn.execute(
                `DELETE FROM AUDIT_TRAIL
                 WHERE changed_by = ?`,
                [userId]
            );

            // g) Delete from VOICE_MESSAGES
            await conn.execute(
                `DELETE FROM VOICE_MESSAGES
                 WHERE user_id = ?`,
                [userId]
            );

            // h) Finally delete from USERS
            const [result] = await conn.execute(
                `DELETE FROM USERS
                 WHERE user_id = ?`,
                [userId]
            );

            if (result.affectedRows === 0) {
                // No such user
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
     * Returns both OBJECT_SCANS and OCR_SCANS for that user, combined and sorted by createdAt DESC.
     */
    getUserScans: async (req, res, next) => {
        try {
            const userId = parseInt(req.params.userId);
            if (isNaN(userId)) {
                return res.status(400).json({ error: 'Invalid userId parameter' });
            }

            // UNION ALL OBJECT_SCANS + OCR_SCANS; label type accordingly
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
                [userId, userId]
            );

            return res.json(rows);
        } catch (err) {
            return next(err);
        }
    },

    /**
     * PUT /api/admin/scans/:scanId
     * Body: { type, name, text }
     * If type='Object', update OBJECT_SCANS row; if 'Text', update OCR_SCANS row.
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
                    error: "Request body must include type ('Object' or 'Text'), name (string), and text (string)."
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
     * Attempts to delete from OCR_SCANS first. If none found, deletes from OBJECT_SCANS.
     */
    deleteScan: async (req, res, next) => {
        try {
            const scanId = parseInt(req.params.scanId);
            if (isNaN(scanId)) {
                return res.status(400).json({ error: 'Invalid scanId parameter' });
            }

            // 1) Try deleting from OCR_SCANS first
            const [ocrDelete] = await pool.execute(
                `DELETE FROM OCR_SCANS
                 WHERE ocr_id = ?`,
                [scanId]
            );
            if (ocrDelete.affectedRows > 0) {
                return res.json({ message: 'OCR scan deleted successfully.' });
            }

            // 2) Otherwise try deleting from OBJECT_SCANS
            const [objDelete] = await pool.execute(
                `DELETE FROM OBJECT_SCANS
                 WHERE scan_id = ?`,
                [scanId]
            );
            if (objDelete.affectedRows > 0) {
                return res.json({ message: 'Object scan deleted successfully.' });
            }

            // 3) If neither table had that ID
            return res.status(404).json({ error: 'Scan not found in either table' });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * GET /api/admin/report?date=YYYY-MM-DD
     * Returns all users whose createdAt date exactly matches the given date.
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
