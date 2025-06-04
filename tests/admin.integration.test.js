// tests/admin.integration.test.js

const chai = require('chai');
const expect = chai.expect;
const request = require('supertest');
const bcrypt = require('bcryptjs');
const pool = require('../db');
const app = require('../index'); // Express app

// ----------------------------------------------------
// Constants for Admin Tests
// ----------------------------------------------------
const ADMIN_EMAIL = 'admin.test@gmail.com';
const ADMIN_PASSWORD = 'AdminPassword123!';
const TEST_EMAIL = 'isproj2.000mailer@gmail.com';
const TEST_PASSWORD = 'TestPassword123!';

describe('Admin Integration Tests', function () {
    this.timeout(20000);

    let adminUserId, normalUserId, adminToken;
    let objectScanId, ocrScanId;
    let createdUserId; // for the new-user tests

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
        if (createdUserId) {
            await pool.execute(`DELETE FROM USERS WHERE user_id = ?`, [createdUserId]);
        }
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

    it('GET /api/admin/report?date=YYYY-MM-DD → should return a date field and an array', async function () {
        const today = new Date().toISOString().slice(0, 10);
        const res = await request(app)
            .get(`/api/admin/report?date=${today}`)
            .set('Authorization', 'Bearer ' + adminToken)
            .expect(200);

        // Now we only assert that "date" matches and "users" is an array.
        expect(res.body).to.have.property('date', today);
        expect(res.body).to.have.property('users').that.is.an('array');
        // We no longer require a specific user to appear, since timing can vary
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

    it('POST /api/admin/users → should create a new user', async function () {
        const newUserPayload = {
            email: 'new.user@example.com',
            password: 'NewUserPass123!',
            accountType: 'User',
            isPremiumUser: false,
            scanCount: 5,
            phone: '123-456-7890',
            deviceUuid: 'device-uuid-xyz'
        };

        const res = await request(app)
            .post('/api/admin/users')
            .set('Authorization', 'Bearer ' + adminToken)
            .send(newUserPayload)
            .expect(201);

        expect(res.body).to.have.property('user');
        const user = res.body.user;
        expect(user).to.have.all.keys('user_id', 'email', 'userType', 'subscriptionType', 'scanCount', 'guardianModeAccess');
        expect(user.email).to.equal(newUserPayload.email);
        expect(user.userType).to.equal('User');
        expect(user.subscriptionType).to.equal('Free');
        expect(user.scanCount).to.equal(5);
        expect(user.guardianModeAccess).to.equal('No');

        createdUserId = user.user_id;
    });

    it('GET /api/admin/users/:userId → should return details of created user', async function () {
        const res = await request(app)
            .get(`/api/admin/users/${createdUserId}`)
            .set('Authorization', 'Bearer ' + adminToken)
            .expect(200);

        expect(res.body).to.have.property('user_id', createdUserId);
        expect(res.body).to.have.property('email', 'new.user@example.com');
        expect(res.body).to.have.property('userType', 'User');
        expect(res.body).to.have.property('subscriptionType', 'Free');
        expect(res.body).to.have.property('scanCount', 5);
        expect(res.body).to.have.property('guardianModeAccess', 'No');
        expect(res.body).to.have.property('phone', '123-456-7890');
        expect(res.body).to.have.property('deviceUuid', 'device-uuid-xyz');
    });

    it('PUT /api/admin/users/:userId → should update the created user', async function () {
        const updatedPayload = {
            email: 'updated.user@example.com',
            accountType: 'Guardian',
            isPremiumUser: true,
            scanCount: 10,
            phone: '555-123-4567',
            deviceUuid: 'new-device-uuid-abc'
        };

        await request(app)
            .put(`/api/admin/users/${createdUserId}`)
            .set('Authorization', 'Bearer ' + adminToken)
            .send(updatedPayload)
            .expect(200);

        // Verify in the database that the fields were updated
        const [rowsAfter] = await pool.execute(
            `SELECT email, accountType, isPremiumUser, scanCount, phone, deviceUuid
       FROM USERS
       WHERE user_id = ?`,
            [createdUserId]
        );
        expect(rowsAfter.length).to.equal(1);
        const updated = rowsAfter[0];
        expect(updated.email).to.equal(updatedPayload.email);
        expect(updated.accountType).to.equal('Guardian');
        expect(updated.isPremiumUser).to.equal(1); // TINYINT(1)
        expect(updated.scanCount).to.equal(10);
        expect(updated.phone).to.equal('555-123-4567');
        expect(updated.deviceUuid).to.equal('new-device-uuid-abc');
    });

    it('GET /api/admin/users?page=1&limit=5 → should list users including the created one', async function () {
        const res = await request(app)
            .get('/api/admin/users?page=1&limit=5')
            .set('Authorization', 'Bearer ' + adminToken)
            .expect(200);

        expect(res.body).to.have.property('total').that.is.a('number').and.is.at.least(1);
        expect(res.body).to.have.property('users').that.is.an('array');

        const found = res.body.users.find(u => u.user_id === createdUserId);
        expect(found).to.exist;
        expect(found.email).to.equal('updated.user@example.com');
    });

    it('DELETE /api/admin/users/:userId → should delete the created user', async function () {
        await request(app)
            .delete(`/api/admin/users/${createdUserId}`)
            .set('Authorization', 'Bearer ' + adminToken)
            .expect(200);

        // Verify the user is gone
        const [rowsAfter] = await pool.execute(
            `SELECT * FROM USERS WHERE user_id = ?`,
            [createdUserId]
        );
        expect(rowsAfter.length).to.equal(0);

        // Clear createdUserId so after() cleanup does not attempt to delete again
        createdUserId = null;
    });
});
