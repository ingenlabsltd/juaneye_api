// utils/otpService.js

const nodemailer = require("nodemailer");
const twilio = require("twilio");
const dotenv = require("dotenv");

dotenv.config();

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

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
        subject: "Your JuanEye Verification Code",
        text:    `Your verification code is: ${codeValue}. It will expire in ${process.env.OTP_EXPIRATION_MINUTES} minutes.`
    });
}

async function sendOTPSMS(toPhone, codeValue) {
    if (!toPhone) {
        console.warn("Attempted to send SMS without a phone number.");
        return;
    }
    try {
        await twilioClient.messages.create({
            body: `Your JuanEye verification code is: ${codeValue}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: toPhone
        });
    } catch (error) {
        console.error("Failed to send OTP SMS:", error);
        // Depending on requirements, you might want to throw the error
        // to be handled by the calling function.
    }
}

module.exports = {
    generateOTP,
    sendOTPEmail,
    sendOTPSMS
};