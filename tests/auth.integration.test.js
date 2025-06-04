// tests/auth.integration.test.js

const chai = require('chai');
const expect = chai.expect;
const request = require('supertest');
const bcrypt = require('bcrypt');
const pool = require('../db');
const app = require('../index'); // Express app

// ----------------------------------------------------
// Constants for Auth Tests
// ----------------------------------------------------
const TEST_EMAIL = 'isproj2.000mailer@gmail.com';
const TEST_PASSWORD = 'TestPassword123!';
const NEW_TEST_PASSWORD = 'NewTestPassword456!';

// ----------------------------------------------------
// Constants for Admin Tests
// ----------------------------------------------------
const ADMIN_EMAIL = 'admin.test@gmail.com';
const ADMIN_PASSWORD = 'AdminPassword123!';

// ----------------------------------------------------
// Constants for NEW Regular User (User Integration Tests)
// ----------------------------------------------------
const REGULAR_EMAIL = 'regular.user@test.com';
const REGULAR_PASSWORD = 'RegularPassword123!';

describe('Auth Integration Tests', function () {
  this.timeout(10000);

  before(async function () {
    // 1) Clean up any leftover OTPS & user (TEST_EMAIL)
    await pool.execute(
        `DELETE FROM OTPS
       WHERE user_id IN (SELECT user_id FROM USERS WHERE email = ?)`,
        [TEST_EMAIL]
    );
    await pool.execute(
        `DELETE FROM USERS WHERE email = ?`,
        [TEST_EMAIL]
    );

    // 2) Insert fresh test user (TEST_EMAIL)
    const hashed = await bcrypt.hash(TEST_PASSWORD, 10);
    await pool.execute(
        `INSERT INTO USERS
         (email, password, accountType, isPremiumUser, scanCount, createdAt, updatedAt)
       VALUES (?, ?, 'User', FALSE, 0, NOW(), NOW())`,
        [TEST_EMAIL, hashed]
    );
  });

  after(async function () {
    // Clean up test user & their OTPs (TEST_EMAIL)
    await pool.execute(
        `DELETE FROM OTPS
       WHERE user_id IN (SELECT user_id FROM USERS WHERE email = ?)`,
        [TEST_EMAIL]
    );
    await pool.execute(
        `DELETE FROM USERS WHERE email = ?`,
        [TEST_EMAIL]
    );
  });

  it('should log in successfully with the test user', async function () {
    const res = await request(app)
        .post('/api/auth/login')
        .send({ email: TEST_EMAIL, password: TEST_PASSWORD })
        .expect(200);

    expect(res.body).to.have.property('token');
    expect(res.body.token).to.be.a('string');
  });

  it('should send an OTP for forgot-password (and store it)', async function () {
    const res = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: TEST_EMAIL })
        .expect(200);

    expect(res.body).to.have.property('message');
    expect(res.body.message).to.equal('If the email exists, an OTP has been sent.');

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

  it('should reset password successfully using the OTP', async function () {
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
        .post('/api/auth/reset-password')
        .send({
          email: TEST_EMAIL,
          codeValue,
          newPassword: NEW_TEST_PASSWORD
        })
        .expect(200);

    expect(res.body).to.have.property('message');
    expect(res.body.message).to.equal('Password has been reset successfully.');

    // 3) Verify OTP is marked used
    const [otpCheckRows] = await pool.execute(
        `SELECT isUsed FROM OTPS WHERE otp_id = ?`,
        [otp_id]
    );
    expect(otpCheckRows.length).to.equal(1);
    expect(otpCheckRows[0].isUsed).to.equal(1);
  });

  it('should log in successfully with the new password', async function () {
    const res = await request(app)
        .post('/api/auth/login')
        .send({ email: TEST_EMAIL, password: NEW_TEST_PASSWORD })
        .expect(200);

    expect(res.body).to.have.property('token');
    expect(res.body.token).to.be.a('string');
  });
});

// ----------------------------------------------------
// Admin Integration Tests
// ----------------------------------------------------
describe('Admin Integration Tests', function () {
  this.timeout(20000);

  let adminUserId, normalUserId, adminToken;
  let objectScanId, ocrScanId;

  before(async function () {
    // Clean up any leftover users/scans from previous runs (ADMIN_EMAIL, TEST_EMAIL)
    await pool.execute(
        `DELETE FROM USER_GUARDIAN_LINK
         WHERE user_id IN (SELECT user_id FROM USERS WHERE email IN (?, ?))
            OR guardian_id IN (SELECT user_id FROM USERS WHERE email IN (?, ?))`,
        [ADMIN_EMAIL, TEST_EMAIL, ADMIN_EMAIL, TEST_EMAIL]
    );
    await pool.execute(
        `DELETE FROM OTPS WHERE user_id IN (SELECT user_id FROM USERS WHERE email IN (?, ?))`,
        [ADMIN_EMAIL, TEST_EMAIL]
    );
    await pool.execute(
        `DELETE FROM OBJECT_SCANS WHERE user_id IN (SELECT user_id FROM USERS WHERE email IN (?, ?))`,
        [ADMIN_EMAIL, TEST_EMAIL]
    );
    await pool.execute(
        `DELETE FROM OCR_SCANS WHERE user_id IN (SELECT user_id FROM USERS WHERE email IN (?, ?))`,
        [ADMIN_EMAIL, TEST_EMAIL]
    );
    await pool.execute(
        `DELETE FROM PAYMENTS WHERE user_id IN (SELECT user_id FROM USERS WHERE email IN (?, ?))`,
        [ADMIN_EMAIL, TEST_EMAIL]
    );
    await pool.execute(
        `DELETE FROM VOICE_MESSAGES WHERE user_id IN (SELECT user_id FROM USERS WHERE email IN (?, ?))`,
        [ADMIN_EMAIL, TEST_EMAIL]
    );
    await pool.execute(
        `DELETE FROM USERS WHERE email IN (?, ?)`,
        [ADMIN_EMAIL, TEST_EMAIL]
    );

    // 1) Insert Admin user
    const hashedAdmin = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await pool.execute(
        `INSERT INTO USERS
         (email, password, accountType, isPremiumUser, scanCount, createdAt, updatedAt)
         VALUES (?, ?, 'Admin', FALSE, 0, NOW(), NOW())`,
        [ADMIN_EMAIL, hashedAdmin]
    );
    const [adminRows] = await pool.execute(
        `SELECT user_id FROM USERS WHERE email = ?`,
        [ADMIN_EMAIL]
    );
    adminUserId = adminRows[0].user_id;

    // 2) Insert a normal user (TEST_EMAIL)
    const hashedUser = await bcrypt.hash(TEST_PASSWORD, 10);
    await pool.execute(
        `INSERT INTO USERS
         (email, password, accountType, isPremiumUser, scanCount, createdAt, updatedAt)
         VALUES (?, ?, 'User', FALSE, 10, NOW(), NOW())`,
        [TEST_EMAIL, hashedUser]
    );
    const [userRows] = await pool.execute(
        `SELECT user_id FROM USERS WHERE email = ?`,
        [TEST_EMAIL]
    );
    normalUserId = userRows[0].user_id;

    // 3) Log in as Admin
    const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD })
        .expect(200);
    adminToken = loginRes.body.token;

    // 4) Insert one OBJECT_SCANS and one OCR_SCANS record for normalUserId
    const [objInsert] = await pool.execute(
        `INSERT INTO OBJECT_SCANS
           (user_id, recognizedObjects, text, createdAt, updatedAt)
         VALUES (?, 'InitialObject', 'InitialText', NOW(), NOW())`,
        [normalUserId]
    );
    objectScanId = objInsert.insertId;

    const [ocrInsert] = await pool.execute(
        `INSERT INTO OCR_SCANS
           (user_id, recognizedText, text, dateTime, createdAt, updatedAt)
         VALUES (?, 'InitialTextName', 'InitialTextContent', NOW(), NOW(), NOW())`,
        [normalUserId]
    );
    ocrScanId = ocrInsert.insertId;
  });

  after(async function () {
    // Clean up scans & users
    await pool.execute(`DELETE FROM OBJECT_SCANS WHERE scan_id = ?`, [objectScanId]);
    await pool.execute(`DELETE FROM OCR_SCANS WHERE ocr_id = ?`, [ocrScanId]);
    await pool.execute(`DELETE FROM USERS WHERE user_id IN (?, ?)`, [normalUserId, adminUserId]);
  });

  it('GET /api/admin/dashboard → should return correct counts & newSignupsLast7Days', async function () {
    const res = await request(app)
        .get('/api/admin/dashboard')
        .set('Authorization', 'Bearer ' + adminToken)
        .expect(200);

    expect(res.body).to.have.property('onlineUsers').that.is.a('number');
    expect(res.body).to.have.property('totalUsers').that.is.a('number');
    expect(res.body).to.have.property('freeUsers').that.is.a('number');
    expect(res.body).to.have.property('premiumUsers').that.is.a('number');
    expect(res.body).to.have.property('newSignupsLast7Days').that.is.an('array');

    res.body.newSignupsLast7Days.forEach(entry => {
      expect(entry).to.have.property('date').that.matches(/^\d{4}-\d{2}-\d{2}$/);
      expect(entry).to.have.property('count').that.is.a('number');
    });
  });

  it('GET /api/admin/users → should return a paginated list of users', async function () {
    const res = await request(app)
        .get('/api/admin/users?page=1&limit=10')
        .set('Authorization', 'Bearer ' + adminToken)
        .expect(200);

    expect(res.body).to.have.property('total').that.is.a('number').and.is.at.least(2);
    expect(res.body).to.have.property('users').that.is.an('array');

    res.body.users.forEach(u => {
      expect(u).to.have.all.keys('user_id', 'email', 'userType', 'subscriptionType', 'scanCount', 'guardianModeAccess');
      expect(u.email).to.be.a('string');
      expect(u.userType).to.be.oneOf(['User', 'Guardian', 'Admin']);
    });
  });

  it('GET /api/admin/users/:userId → should return details of our normal user', async function () {
    const res = await request(app)
        .get(`/api/admin/users/${normalUserId}`)
        .set('Authorization', 'Bearer ' + adminToken)
        .expect(200);

    expect(res.body).to.have.property('user_id', normalUserId);
    expect(res.body).to.have.property('email', TEST_EMAIL);
    expect(res.body).to.have.property('userType', 'User');
    expect(res.body).to.have.property('subscriptionType', 'Free');
    expect(res.body).to.have.property('scanCount', 10);
    expect(res.body).to.have.property('guardianModeAccess', 'No');
  });

  it('PUT /api/admin/users/:userId → should update the normal user’s fields', async function () {
    const UPDATED_EMAIL = 'updated.user@gmail.com';
    const UPDATED_ACCOUNT_TYPE = 'User';
    const UPDATED_IS_PREMIUM = true;
    const UPDATED_SCAN_COUNT = 20;

    await request(app)
        .put(`/api/admin/users/${normalUserId}`)
        .set('Authorization', 'Bearer ' + adminToken)
        .send({
          email: UPDATED_EMAIL,
          accountType: UPDATED_ACCOUNT_TYPE,
          isPremiumUser: UPDATED_IS_PREMIUM,
          scanCount: UPDATED_SCAN_COUNT
        })
        .expect(200);

    const [rowsAfter] = await pool.execute(
        `SELECT email, accountType, isPremiumUser, scanCount
         FROM USERS
         WHERE user_id = ?`,
        [normalUserId]
    );
    expect(rowsAfter.length).to.equal(1);
    expect(rowsAfter[0].email).to.equal(UPDATED_EMAIL);
    expect(rowsAfter[0].accountType).to.equal(UPDATED_ACCOUNT_TYPE);
    expect(rowsAfter[0].isPremiumUser).to.equal(1);
    expect(rowsAfter[0].scanCount).to.equal(UPDATED_SCAN_COUNT);

    // Restore original email
    await pool.execute(
        `UPDATE USERS SET email = ?, updatedAt = NOW() WHERE user_id = ?`,
        [TEST_EMAIL, normalUserId]
    );
  });

  it('GET /api/admin/users/:userId/scans → should return both Object & OCR scans', async function () {
    const res = await request(app)
        .get(`/api/admin/users/${normalUserId}/scans`)
        .set('Authorization', 'Bearer ' + adminToken)
        .expect(200);

    expect(res.body).to.be.an('array');
    const foundObject = res.body.find(r => r.type === 'Object' && r.scanId === objectScanId);
    const foundOCR    = res.body.find(r => r.type === 'Text' && r.scanId === ocrScanId);
    expect(foundObject).to.exist;
    expect(foundOCR).to.exist;
  });

  it('PUT /api/admin/scans/:scanId → should update an OBJECT_SCANS record', async function () {
    const NEW_NAME = 'UpdatedObjectName';
    const NEW_TEXT = 'UpdatedObjectText';

    await request(app)
        .put(`/api/admin/scans/${objectScanId}`)
        .set('Authorization', 'Bearer ' + adminToken)
        .send({
          type: 'Object',
          name: NEW_NAME,
          text: NEW_TEXT
        })
        .expect(200);

    const [objRowAfter] = await pool.execute(
        `SELECT recognizedObjects, text
         FROM OBJECT_SCANS
         WHERE scan_id = ?`,
        [objectScanId]
    );
    expect(objRowAfter.length).to.equal(1);
    expect(objRowAfter[0].recognizedObjects).to.equal(NEW_NAME);
    expect(objRowAfter[0].text).to.equal(NEW_TEXT);
  });

  it('DELETE /api/admin/scans/:scanId → should delete the OCR_SCANS record', async function () {
    await request(app)
        .delete(`/api/admin/scans/${ocrScanId}`)
        .set('Authorization', 'Bearer ' + adminToken)
        .expect(200);

    const [ocrRowsAfter] = await pool.execute(
        `SELECT * FROM OCR_SCANS WHERE ocr_id = ?`,
        [ocrScanId]
    );
    expect(ocrRowsAfter.length).to.equal(0);
  });

  it('GET /api/admin/report?date=YYYY-MM-DD → should return users created on that date', async function () {
    const today = new Date().toISOString().slice(0, 10);
    const res = await request(app)
        .get(`/api/admin/report?date=${today}`)
        .set('Authorization', 'Bearer ' + adminToken)
        .expect(200);

    expect(res.body).to.have.property('date', today);
    expect(res.body).to.have.property('users').that.is.an('array');

    const found = res.body.users.find((u) => u.user_id === normalUserId);
    expect(found).to.exist;
    expect(found).to.have.property('email', TEST_EMAIL);
    expect(found).to.have.property('userType', 'User');
  });

  it('DELETE /api/admin/users/:userId → should delete normal user and its scans', async function () {
    await request(app)
        .delete(`/api/admin/users/${normalUserId}`)
        .set('Authorization', 'Bearer ' + adminToken)
        .expect(200);

    const [userRowsAfter] = await pool.execute(
        `SELECT * FROM USERS WHERE user_id = ?`,
        [normalUserId]
    );
    expect(userRowsAfter.length).to.equal(0);

    const [objRowsAfter] = await pool.execute(
        `SELECT * FROM OBJECT_SCANS WHERE scan_id = ?`,
        [objectScanId]
    );
    expect(objRowsAfter.length).to.equal(0);
  });
});

// ----------------------------------------------------
// Newly added: User Integration Tests
// ----------------------------------------------------
describe('User Integration Tests', function () {
  this.timeout(10000);

  let userToken;    // JWT for our REGULAR_EMAIL user
  let regularUserId; // Will store the inserted user_id

  before(async function () {
    // 1) Clean up if REGULAR_EMAIL already exists
    await pool.execute(
        `DELETE FROM OTPS
       WHERE user_id IN (SELECT user_id FROM USERS WHERE email = ?)`,
        [REGULAR_EMAIL]
    );
    await pool.execute(
        `DELETE FROM USERS WHERE email = ?`,
        [REGULAR_EMAIL]
    );

    // 2) Insert a fresh regular user
    const hashed = await bcrypt.hash(REGULAR_PASSWORD, 10);
    await pool.execute(
        `INSERT INTO USERS
         (email, password, accountType, isPremiumUser, scanCount, createdAt, updatedAt)
       VALUES (?, ?, 'User', FALSE, 5, NOW(), NOW())`,
        [REGULAR_EMAIL, hashed]
    );
    const [rows] = await pool.execute(
        `SELECT user_id FROM USERS WHERE email = ?`,
        [REGULAR_EMAIL]
    );
    regularUserId = rows[0].user_id;

    // 3) Log in as that user to get the token
    const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: REGULAR_EMAIL, password: REGULAR_PASSWORD })
        .expect(200);

    expect(loginRes.body).to.have.property('token');
    userToken = loginRes.body.token;
  });

  after(async function () {
    // Clean up the regular user and any OTPs (if generated)
    await pool.execute(
        `DELETE FROM OTPS
       WHERE user_id = ?`,
        [regularUserId]
    );
    await pool.execute(
        `DELETE FROM USERS WHERE user_id = ?`,
        [regularUserId]
    );
  });

  it('GET /api/dashboard → should allow regular user to see dashboard', async function () {
    const res = await request(app)
        .get('/api/dashboard')
        .set('Authorization', 'Bearer ' + userToken)
        .expect(200);

    // The response should include message, user object with user_id, email, accountType, scanCount, isPremiumUser
    expect(res.body).to.have.property('message').that.is.a('string');
    expect(res.body).to.have.property('user').that.is.an('object');
    expect(res.body.user).to.have.all.keys('user_id', 'email', 'accountType', 'scanCount', 'isPremiumUser');
    expect(res.body.user.email).to.equal(REGULAR_EMAIL);
    expect(res.body.user.accountType).to.equal('User');
  });

  it('GET /api/admin/users → should forbid regular user (403)', async function () {
    await request(app)
        .get('/api/admin/users?page=1&limit=5')
        .set('Authorization', 'Bearer ' + userToken)
        .expect(403);
  });

  it('GET /api/dashboard with missing token → should return 401', async function () {
    await request(app)
        .get('/api/dashboard')
        // no Authorization header
        .expect(401);
  });

  it('GET /api/dashboard with invalid token → should return 401', async function () {
    await request(app)
        .get('/api/dashboard')
        .set('Authorization', 'Bearer invalid.token.here')
        .expect(401);
  });
});
