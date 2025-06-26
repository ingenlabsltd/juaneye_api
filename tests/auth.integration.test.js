// tests/auth.integration.test.js

const chai    = require("chai");
const expect  = chai.expect;
const request = require("supertest");
const bcrypt  = require("bcryptjs");
const pool    = require("../db");
const app     = require("../index"); // Express app

// ----------------------------------------------------
// Constants for Auth Tests
// ----------------------------------------------------
const TEST_EMAIL        = "isproj2.000mailer@gmail.com";
const TEST_PASSWORD     = "TestPassword123!";
const NEW_TEST_PASSWORD = "NewTestPassword456!";

// ⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅
// New signup constants:
const SIGNUP_EMAIL     = "signup_test@example.com";
const SIGNUP_PASSWORD  = "SignupPass123!";
// ⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅

describe("Auth Integration Tests", function () {
  this.timeout(10000);

  before(async function () {
    // 1) Clean up any leftover OTPS & users for BOTH TEST_EMAIL and SIGNUP_EMAIL
    for (const email of [TEST_EMAIL, SIGNUP_EMAIL]) {
      await pool.execute(
          `DELETE FROM OTPS
         WHERE user_id IN (SELECT user_id FROM USERS WHERE email = ?)`,
          [email]
      );
      await pool.execute(
          `DELETE FROM USERS WHERE email = ?`,
          [email]
      );
    }

    // 2) Insert fresh test user (TEST_EMAIL) for forgot/reset flow
    const hashed = await bcrypt.hash(TEST_PASSWORD, 10);
    await pool.execute(
        `INSERT INTO USERS
         (email, password, accountType, isPremiumUser, scanCount, createdAt, updatedAt)
         VALUES (?, ?, 'User', FALSE, 0, NOW(), NOW())`,
        [TEST_EMAIL, hashed]
    );
  });

  after(async function () {
    // Clean up test users & their OTPs for BOTH TEST_EMAIL and SIGNUP_EMAIL
    for (const email of [TEST_EMAIL, SIGNUP_EMAIL]) {
      await pool.execute(
          `DELETE FROM OTPS
         WHERE user_id IN (SELECT user_id FROM USERS WHERE email = ?)`,
          [email]
      );
      await pool.execute(
          `DELETE FROM USERS WHERE email = ?`,
          [email]
      );
    }
  });

  // ────────────────────────────────────────────────────────────────
  // New: Signup + Login tests for SIGNUP_EMAIL
  // ────────────────────────────────────────────────────────────────

  it("should sign up a new user", async function () {
    const res = await request(app)
        .post("/api/auth/signup")
        .send({ email: SIGNUP_EMAIL, password: SIGNUP_PASSWORD })
        .expect(201);

    expect(res.body).to.have.property("message", "Signup successful");
    expect(res.body).to.have.property("userId").that.is.a("number");
    expect(res.body).to.have.property("token").that.is.a("string");
  });

  it("should log in successfully with the newly signed-up user", async function () {
    const res = await request(app)
        .post("/api/auth/login")
        .send({ email: SIGNUP_EMAIL, password: SIGNUP_PASSWORD })
        .expect(200);

    expect(res.body).to.have.property("token").that.is.a("string");
  });

  // ────────────────────────────────────────────────────────────────
  // Original tests (unchanged)
  // ────────────────────────────────────────────────────────────────

  it("should log in successfully with the test user", async function () {
    const res = await request(app)
        .post("/api/auth/login")
        .send({ email: TEST_EMAIL, password: TEST_PASSWORD })
        .expect(200);

    expect(res.body).to.have.property("token");
    expect(res.body.token).to.be.a("string");
  });

  it("should send an OTP for forgot-password (and store it)", async function () {
    const res = await request(app)
        .post("/api/auth/forgot-password")
        .send({ email: TEST_EMAIL })
        .expect(200);

    expect(res.body).to.have.property("message");
    expect(res.body.message).to.equal("If that email exists, OTP sent.");

    // Verify that an OTP row exists (isUsed = FALSE)
    const [otpRows] = await pool.execute(
        `SELECT otp_id, isUsed
         FROM OTPS
         WHERE user_id = (SELECT user_id FROM USERS WHERE email = ?)
         ORDER BY createdAt DESC
           LIMIT 1`,
        [TEST_EMAIL]
    );
    expect(otpRows.length).to.equal(1);
    expect(otpRows[0].isUsed).to.equal(0);
  });

  it("should reset password successfully using the OTP", async function () {
    // 1) Fetch the most recent OTP
    const [otpRows] = await pool.execute(
        `SELECT otp_id, codeValue
         FROM OTPS
         WHERE user_id = (SELECT user_id FROM USERS WHERE email = ?)
           AND isUsed = FALSE
         ORDER BY createdAt DESC
           LIMIT 1`,
        [TEST_EMAIL]
    );
    expect(otpRows.length).to.equal(1);
    const { codeValue, otp_id } = otpRows[0];

    // 2) Call reset-password
    const res = await request(app)
        .post("/api/auth/reset-password")
        .send({
          email: TEST_EMAIL,
          codeValue: codeValue,
          newPassword: NEW_TEST_PASSWORD
        })
        .expect(200);

    expect(res.body).to.have.property("message");
    expect(res.body.message).to.equal("Password reset successful.");

    // 3) Verify OTP is marked used
    const [otpCheckRows] = await pool.execute(
        `SELECT isUsed FROM OTPS WHERE otp_id = ?`,
        [otp_id]
    );
    expect(otpCheckRows.length).to.equal(1);
    expect(otpCheckRows[0].isUsed).to.equal(1);
  });

  it("should log in successfully with the new password", async function () {
    const res = await request(app)
        .post("/api/auth/login")
        .send({ email: TEST_EMAIL, password: NEW_TEST_PASSWORD })
        .expect(200);

    expect(res.body).to.have.property("token");
    expect(res.body.token).to.be.a("string");
  });
});
