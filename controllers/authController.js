// controllers/authController.js

const pool = require("../db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const { generateOTP, sendOTPEmail, sendOTPSMS } = require("../utils/otpService");

dotenv.config();

/**
 * Returns true if password is at least 8 chars,
 * contains uppercase, lowercase, digit, and special char.
 */
function isStrongPassword(password) {
    const strongPwdRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
    return strongPwdRegex.test(password);
}

/**
 * Returns true if email is in valid format.
 */
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// ─── Controller exports ─────────────────────────────────────────────────────

module.exports = {
    /**
     * POST /api/auth/signup
     * Body: { email, password, accountType }
     * Creates a new user (email+hashed password) and returns userId + JWT.
     */
    signup: async (req, res, next) => {
        const { email, phone, password } = req.body;
        let accountType = req.body.accountType || "User";

        if ((!email && !phone) || !password) {
            return res
                .status(400)
                .json({ error: "Email or phone number, and password are required." });
        }

        if (email && !isValidEmail(email)) {
            return res.status(400).json({ error: "Invalid email format." });
        }

        // Validate password strength
        if (!isStrongPassword(password)) {
            return res
                .status(400)
                .json({
                    error: "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character."
                });
        }

        try {
            // 1) Check for existing email or phone
            let existingUser;
            if (email) {
                const [rows] = await pool.execute("SELECT user_id FROM USERS WHERE email = ?", [email]);
                if (rows.length > 0) {
                    return res.status(409).json({ error: "That email is already registered." });
                }
            }
            if (phone) {
                const [rows] = await pool.execute("SELECT user_id FROM USERS WHERE phone = ?", [phone]);
                if (rows.length > 0) {
                    return res.status(409).json({ error: "That phone number is already registered." });
                }
            }

            // 2) Hash password & insert
            const hashed = await bcrypt.hash(password, 10);
            const [result] = await pool.execute(
                "INSERT INTO USERS (email, phone, password, accountType) VALUES (?, ?, ?, ?)",
                [email || null, phone || null, hashed, accountType]
            );
            const userId = result.insertId;

            // 3) Generate and send OTP
            const codeValue = generateOTP();
            const expirationTime = new Date(
                Date.now() +
                parseInt(process.env.OTP_EXPIRATION_MINUTES, 10) * 60_000
            );
            await pool.execute(
                `INSERT INTO OTPS (user_id, codeValue, expirationTime, isUsed, createdAt, updatedAt)
                 VALUES (?, ?, ?, FALSE, NOW(), NOW())`,
                [userId, codeValue, expirationTime]
            );

            if (email) {
                await sendOTPEmail(email, codeValue);
            }
            if (phone) {
                await sendOTPEmail(email, codeValue);
            }
            if (phone) {
                // Make sure to pass the phone number to the SMS function
                await sendOTPSMS(phone, codeValue);
            }

            // 4) Respond
            return res.status(201).json({
                message: "Signup successful. Please verify your OTP.",
                userId
            });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * POST /api/auth/verify-signup
     * Body: { email, phone, codeValue }
     * Verifies the signup OTP and returns a JWT.
     */
    verifySignupOTP: async (req, res, next) => {
        const { email, phone, codeValue } = req.body;
        if ((!email && !phone) || !codeValue) {
            return res.status(400).json({ error: "Email or phone, and code are required." });
        }

        try {
            let user;
            if (email) {
                const [rows] = await pool.execute("SELECT * FROM USERS WHERE email = ?", [email]);
                if (rows.length === 0) {
                    return res.status(401).json({ error: "Invalid credentials." });
                }
                user = rows[0];
            } else {
                const [rows] = await pool.execute("SELECT * FROM USERS WHERE phone = ?", [phone]);
                if (rows.length === 0) {
                    return res.status(401).json({ error: "Invalid credentials." });
                }
                user = rows[0];
            }

            const [otps] = await pool.execute(
                `SELECT otp_id, expirationTime FROM OTPS WHERE user_id = ? AND codeValue = ? AND isUsed = FALSE ORDER BY createdAt DESC LIMIT 1`,
                [user.user_id, codeValue]
            );

            if (otps.length === 0) {
                return res.status(400).json({ error: "Invalid or expired OTP." });
            }

            const otp = otps[0];
            if (new Date(otp.expirationTime) < new Date()) {
                return res.status(400).json({ error: "OTP has expired." });
            }

            await pool.execute("UPDATE OTPS SET isUsed = TRUE, updatedAt = NOW() WHERE otp_id = ?", [otp.otp_id]);

            const token = jwt.sign(
                {
                    user_id: user.user_id,
                    email: user.email,
                    phone: user.phone,
                    accountType: user.accountType,
                    isPremiumUser: user.isPremiumUser
                },
                process.env.JWT_SECRET,
                { expiresIn: "2h" }
            );

            return res.json({ token });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * POST /api/auth/login
     * Body: { email, phone, password }
     * Verifies credentials and returns a JWT.
     */
    login: async (req, res, next) => {
        const { email, phone, password } = req.body;
        if ((!email && !phone) || !password) {
            return res
                .status(400)
                .json({ error: "Email or phone, and password are required." });
        }

        if (email && !isValidEmail(email)) {
            return res
                .status(400)
                .json({ error: "Invalid email format." });
        }

        try {
            // 1) Fetch user row
            let user;
            if (email) {
                const [rows] = await pool.execute("SELECT * FROM USERS WHERE email = ?", [email]);
                if (rows.length === 0) {
                    return res.status(401).json({ error: "Invalid credentials." });
                }
                user = rows[0];
            } else {
                const [rows] = await pool.execute("SELECT * FROM USERS WHERE phone = ?", [phone]);
                if (rows.length === 0) {
                    return res.status(401).json({ error: "Invalid credentials." });
                }
                user = rows[0];
            }

            // 2) Compare password
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return res.status(401).json({ error: "Invalid credentials." });
            }

            // 3) Generate and send OTP
            const codeValue = generateOTP();
            const expirationTime = new Date(
                Date.now() +
                parseInt(process.env.OTP_EXPIRATION_MINUTES, 10) * 60_000
            );
            await pool.execute(
                `INSERT INTO OTPS
                     (user_id, codeValue, expirationTime, isUsed, createdAt, updatedAt)
                 VALUES (?, ?, ?, FALSE, NOW(), NOW())`,
                [user.user_id, codeValue, expirationTime]
            );

            if (user.email) {
                await sendOTPEmail(user.email, codeValue);
            }
            if (user.phone) {
                await sendOTPSMS(user.phone, codeValue);
            }

            // 4) Respond
            return res.json({ message: "OTP sent to your registered contact methods." });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * POST /api/auth/verify-login
     * Body: { email, codeValue }
     * Verifies the login OTP and returns a JWT.
     */
    verifyLoginOTP: async (req, res, next) => {
        const { email, codeValue } = req.body;
        if (!email || !codeValue) {
            return res
                .status(400)
                .json({ error: "Email and code are required." });
        }

        try {
            // 1) Find user
            const [users] = await pool.execute(
                "SELECT * FROM USERS WHERE email = ?",
                [email]
            );
            if (users.length === 0) {
                return res.status(401).json({ error: "Invalid credentials." });
            }
            const user = users[0];

            // 2) Find matching OTP
            const [otps] = await pool.execute(
                `SELECT otp_id, expirationTime
                 FROM OTPS
                 WHERE user_id = ?
                   AND codeValue = ?
                   AND isUsed = FALSE
                 ORDER BY createdAt DESC
                     LIMIT 1`,
                [user.user_id, codeValue]
            );
            if (otps.length === 0) {
                return res.status(400).json({ error: "Invalid or expired OTP." });
            }
            const otp = otps[0];
            if (new Date(otp.expirationTime) < new Date()) {
                return res.status(400).json({ error: "OTP has expired." });
            }

            // 3) Mark OTP as used and sign JWT
            await pool.execute(
                "UPDATE OTPS SET isUsed = TRUE, updatedAt = NOW() WHERE otp_id = ?",
                [otp.otp_id]
            );
            const token = jwt.sign(
                {
                    user_id:       user.user_id,
                    email:         user.email,
                    accountType:   user.accountType,
                    isPremiumUser: user.isPremiumUser
                },
                process.env.JWT_SECRET,
                { expiresIn: "2h" }
            );

            // 4) Respond
            return res.json({ token });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * POST /api/auth/forgot-password
     * Body: { email, phone }
     * Generates and emails/SMS a one-time OTP.
     */
    forgotPassword: async (req, res, next) => {
        const { email, phone } = req.body;
        if (!email && !phone) {
            return res.status(400).json({ error: "Email or phone is required." });
        }

        if (email && !isValidEmail(email)) {
            return res
                .status(400)
                .json({ error: "Invalid email format." });
        }

        try {
            // 1) Lookup user
            let user;
            if (email) {
                const [rows] = await pool.execute("SELECT * FROM USERS WHERE email = ?", [email]);
                user = rows[0];
            } else {
                const [rows] = await pool.execute("SELECT * FROM USERS WHERE phone = ?", [phone]);
                user = rows[0];
            }

            if (!user) {
                // Don’t reveal existence
                return res.json({ message: "If an account with that contact method exists, an OTP has been sent." });
            }

            // 2) Create OTP record
            const codeValue = generateOTP();
            const expirationTime = new Date(
                Date.now() +
                parseInt(process.env.OTP_EXPIRATION_MINUTES, 10) * 60_000
            );
            await pool.execute(
                `INSERT INTO OTPS
                     (user_id, codeValue, expirationTime, isUsed, createdAt, updatedAt)
                 VALUES (?, ?, ?, FALSE, NOW(), NOW())`,
                [user.user_id, codeValue, expirationTime]
            );

            // 3) Email and/or SMS it
            if (user.email) {
                await sendOTPEmail(user.email, codeValue);
            }
            if (user.phone) {
                await sendOTPSMS(user.phone, codeValue);
            }

            return res.json({ message: "If an account with that contact method exists, an OTP has been sent." });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * POST /api/auth/reset-password
     * Body: { email, phone, codeValue, newPassword }
     * Validates OTP and updates the user’s password.
     */
    resetPassword: async (req, res, next) => {
        const { email, phone, codeValue, newPassword } = req.body;
        if ((!email && !phone) || !codeValue || !newPassword) {
            return res
                .status(400)
                .json({ error: "Email or phone, codeValue, and newPassword are required." });
        }

        if (email && !isValidEmail(email)) {
            return res
                .status(400)
                .json({ error: "Invalid email format." });
        }

        // Validate new password strength
        if (!isStrongPassword(newPassword)) {
            return res
                .status(400)
                .json({
                    error: "New password must be at least 8 characters long and include uppercase, lowercase, number, and special character."
                });
        }

        try {
            // 1) Lookup user
            let user;
            if (email) {
                const [rows] = await pool.execute("SELECT * FROM USERS WHERE email = ?", [email]);
                user = rows[0];
            } else {
                const [rows] = await pool.execute("SELECT * FROM USERS WHERE phone = ?", [phone]);
                user = rows[0];
            }

            if (!user) {
                return res.status(400).json({ error: "Invalid contact method or OTP." });
            }
            const userId = user.user_id;

            // 2) Find matching OTP
            const [otps] = await pool.execute(
                `SELECT otp_id, expirationTime
                 FROM OTPS
                 WHERE user_id = ?
                   AND codeValue = ?
                   AND isUsed = FALSE
                 ORDER BY createdAt DESC
                     LIMIT 1`,
                [userId, codeValue]
            );
            if (otps.length === 0) {
                return res.status(400).json({ error: "Invalid or expired OTP." });
            }
            const otp = otps[0];
            if (new Date(otp.expirationTime) < new Date()) {
                return res.status(400).json({ error: "OTP has expired." });
            }

            // 3) Hash new password & update in a transaction
            const conn = await pool.getConnection();
            try {
                await conn.beginTransaction();

                await conn.execute(
                    "UPDATE OTPS SET isUsed = TRUE, updatedAt = NOW() WHERE otp_id = ?",
                    [otp.otp_id]
                );

                const hashed = await bcrypt.hash(newPassword, 10);
                await conn.execute(
                    "UPDATE USERS SET password = ?, updatedAt = NOW() WHERE user_id = ?",
                    [hashed, userId]
                );

                await conn.commit();
            } catch (txErr) {
                await conn.rollback();
                throw txErr;
            } finally {
                conn.release();
            }

            return res.json({ message: "Password reset successful." });
        } catch (err) {
            return next(err);
        }
    }
};
