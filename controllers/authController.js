// controllers/authController.js
const pool = require('../db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

// Utility: generate a random 6-digit OTP as a string
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Utility: send OTP via email
async function sendOTPEmail(toEmail, codeValue) {
    // Configure nodemailer transporter
    const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        },
        tls: {
            rejectUnauthorized: false
        }
    });

    const mailOptions = {
        from: 'isproj2.000mailer@gmail.com',
        to: toEmail,
        subject: 'Your Password Reset Code',
        text: `Your OTP code for password reset is: ${codeValue}. It will expire in ${process.env.OTP_EXPIRATION_MINUTES} minutes.`
    };

    await transporter.sendMail(mailOptions);
}

module.exports = {
    /**
     * POST /api/auth/login
     * Body: { email: string, password: string }
     * Verifies credentials, returns JWT on success.
     */
    login: async (req, res, next) => {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required.' });
        }

        try {
            // 1. Fetch the user by email
            const [rows] = await pool.execute(
                'SELECT user_id, email, password, accountType FROM USERS WHERE email = ?',
                [email]
            );

            if (rows.length === 0) {
                return res.status(401).json({ error: 'Invalid email or password.' });
            }

            const user = rows[0];

            // 2. Compare supplied password with stored hashed password
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) {
                return res.status(401).json({ error: 'Invalid email or password.' });
            }

            // 3. Generate a JWT
            const payload = {
                user_id: user.user_id,
                email: user.email,
                accountType: user.accountType
            };
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '2h' });

            // 4. Respond with token
            return res.json({ token });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * POST /api/auth/forgot-password
     * Body: { email: string }
     * Generates an OTP and sends it to the user's email.
     */
    forgotPassword: async (req, res, next) => {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email is required.' });
        }

        try {
            // 1. Check if a user with this email exists
            const [userRows] = await pool.execute(
                'SELECT user_id FROM USERS WHERE email = ?',
                [email]
            );

            if (userRows.length === 0) {
                // We do not reveal whether the email exists or not
                return res.status(200).json({ message: 'If the email exists, you will receive an OTP.' });
            }

            const userId = userRows[0].user_id;

            // 2. Generate a 6-digit OTP
            const codeValue = generateOTP();

            // 3. Calculate expiration time based on OTP_EXPIRATION_MINUTES
            const expirationTime = new Date(Date.now() + parseInt(process.env.OTP_EXPIRATION_MINUTES) * 60000);

            // 4. Insert OTP into OTPS table
            await pool.execute(
                `INSERT INTO OTPS (user_id, codeValue, expirationTime, isUsed, createdAt, updatedAt)
         VALUES (?, ?, ?, FALSE, NOW(), NOW())`,
                [userId, codeValue, expirationTime]
            );

            // 5. Send the OTP to the user's email
            await sendOTPEmail(email, codeValue);

            return res.json({ message: 'If the email exists, an OTP has been sent.' });
        } catch (err) {
            return next(err);
        }
    },

    /**
     * POST /api/auth/reset-password
     * Body: { email: string, codeValue: string, newPassword: string }
     * Validates the OTP and updates the user's password if valid.
     */
    resetPassword: async (req, res, next) => {
        const { email, codeValue, newPassword } = req.body;

        // Validate input
        if (!email || !codeValue || !newPassword) {
            return res.status(400).json({ error: 'Email, codeValue, and newPassword are required.' });
        }

        try {
            // 1. Fetch user by email
            const [userRows] = await pool.execute(
                'SELECT user_id FROM USERS WHERE email = ?',
                [email]
            );
            if (userRows.length === 0) {
                return res.status(400).json({ error: 'Invalid email or OTP.' });
            }
            const userId = userRows[0].user_id;

            // 2. Fetch OTP row that matches user_id, codeValue, isUsed = FALSE, and not expired
            const [otpRows] = await pool.execute(
                `SELECT otp_id, expirationTime, isUsed
         FROM OTPS
         WHERE user_id = ? AND codeValue = ? AND isUsed = FALSE
         ORDER BY createdAt DESC
         LIMIT 1`,
                [userId, codeValue]
            );

            if (otpRows.length === 0) {
                return res.status(400).json({ error: 'Invalid or expired OTP.' });
            }

            const otpRecord = otpRows[0];
            const now = new Date();

            // 3. Check if OTP is expired
            if (new Date(otpRecord.expirationTime) < now) {
                return res.status(400).json({ error: 'OTP has expired.' });
            }

            // 4. Hash the new password
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

            // 5. Begin transaction: mark OTP used and update the user's password
            const conn = await pool.getConnection();
            try {
                await conn.beginTransaction();

                // a) Mark OTP as used
                await conn.execute(
                    `UPDATE OTPS
           SET isUsed = TRUE, updatedAt = NOW()
           WHERE otp_id = ?`,
                    [otpRecord.otp_id]
                );

                // b) Update user's password
                await conn.execute(
                    `UPDATE USERS
           SET password = ?, updatedAt = NOW()
           WHERE user_id = ?`,
                    [hashedPassword, userId]
                );

                await conn.commit();
            } catch (txErr) {
                await conn.rollback();
                conn.release();
                throw txErr;
            }
            conn.release();

            return res.json({ message: 'Password has been reset successfully.' });
        } catch (err) {
            return next(err);
        }
    }
};
