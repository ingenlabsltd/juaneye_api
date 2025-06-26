// controllers/authController.js

const pool       = require("../db");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const dotenv     = require("dotenv");
dotenv.config();

// ─── Helpers for OTP flows (unchanged) ───────────────────────────────────────

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTPEmail(toEmail, codeValue) {
    const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        },
        tls: { rejectUnauthorized: false }
    });

    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to:   toEmail,
        subject: "Your Password Reset Code",
        text:    `Your OTP code is: ${codeValue}. Expires in ${process.env.OTP_EXPIRATION_MINUTES} minutes.`
    });
}

// ─── Controller exports ─────────────────────────────────────────────────────

module.exports = {
    /**
     * POST /api/auth/signup
     * Body: { email, password, accountType }
     * Creates a new user (email+hashed password) and returns userId + JWT.
     */
    signup: async (req, res, next) => {
        const { email, password, accountType } = req.body;
        if (!email || !password) {
            return res
                .status(400)
                .json({ error: "Email and password are required." });
        }

        try {
            // 1) Check for existing email
            const [rows] = await pool.execute(
                "SELECT user_id FROM USERS WHERE email = ?",
                [email]
            );
            if (rows.length > 0) {
                return res
                    .status(409)
                    .json({ error: "That email is already registered." });
            }

            // 2) Hash password & insert
            const hashed = await bcrypt.hash(password, 10);
            const [result] = await pool.execute(
                "INSERT INTO USERS (email, password, accountType) VALUES (?, ?)",
                [email, hashed]
            );
            const userId = result.insertId;

            // 3) (Optional) Immediately sign a JWT
            const token = jwt.sign(
                { user_id: userId, email },
                process.env.JWT_SECRET,
                { expiresIn: "2h" }
            );

            // 4) Respond
            return res.status(201).json({
                message: "Signup successful",
                userId,
                token
            });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * POST /api/auth/login
     * Body: { email, password }
     * Verifies credentials and returns a JWT.
     */
    login: async (req, res, next) => {
        const { email, password } = req.body;
        if (!email || !password) {
            return res
                .status(400)
                .json({ error: "Email and password are required." });
        }

        try {
            // 1) Fetch user row
            const [rows] = await pool.execute(
                "SELECT user_id, password, accountType FROM USERS WHERE email = ?",
                [email]
            );
            if (rows.length === 0) {
                return res.status(401).json({ error: "Invalid credentials." });
            }
            const user = rows[0];

            // 2) Compare password
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return res.status(401).json({ error: "Invalid credentials." });
            }

            // 3) Sign JWT
            const token = jwt.sign(
                {
                    user_id:     user.user_id,
                    email:       user.email,
                    accountType: user.accountType
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
     * Body: { email }
     * Generates and emails a one-time OTP.
     */
    forgotPassword: async (req, res, next) => {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: "Email is required." });
        }
        try {
            // 1) Lookup user
            const [users] = await pool.execute(
                "SELECT user_id FROM USERS WHERE email = ?",
                [email]
            );
            if (users.length === 0) {
                // Don’t reveal existence
                return res.json({ message: "If that email exists, OTP sent." });
            }
            const userId = users[0].user_id;

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
                [userId, codeValue, expirationTime]
            );

            // 3) Email it
            await sendOTPEmail(email, codeValue);

            return res.json({ message: "If that email exists, OTP sent." });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * POST /api/auth/reset-password
     * Body: { email, codeValue, newPassword }
     * Validates OTP and updates the user’s password.
     */
    resetPassword: async (req, res, next) => {
        const { email, codeValue, newPassword } = req.body;
        if (!email || !codeValue || !newPassword) {
            return res
                .status(400)
                .json({ error: "Email, codeValue, and newPassword are required." });
        }

        try {
            // 1) Lookup user
            const [users] = await pool.execute(
                "SELECT user_id FROM USERS WHERE email = ?",
                [email]
            );
            if (users.length === 0) {
                return res.status(400).json({ error: "Invalid email/OTP." });
            }
            const userId = users[0].user_id;

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
