const chai = require('chai');
const expect = chai.expect;
const request = require('supertest');
const bcrypt = require('bcryptjs');
const pool = require('../db');
const app = require('../index');

describe('User Integration Tests', function () {
    this.timeout(20000);

    const REGULAR_EMAIL = 'regular.user@test.com';
    const REGULAR_PASSWORD = 'RegularPassword123!';
    let regularUserId;
    let userToken;
    let ocrScanId;
    let objectScanId;

    before(async function () {
        // Cleanup OTPs for any existing user with this email
        await pool.execute(
            `DELETE FROM OTPS WHERE user_id IN (SELECT user_id FROM USERS WHERE email = ?)`,
            [REGULAR_EMAIL]
        );

        // ─── ALSO clean up any existing scans (to avoid FK errors) ────────────────
        await pool.execute(
            `DELETE FROM OCR_SCANS WHERE user_id IN (SELECT user_id FROM USERS WHERE email = ?)`,
            [REGULAR_EMAIL]
        );
        await pool.execute(
            `DELETE FROM OBJECT_SCANS WHERE user_id IN (SELECT user_id FROM USERS WHERE email = ?)`,
            [REGULAR_EMAIL]
        );

        // If you use guardian links in other tests, you might also clean those here
        // await pool.execute(
        //     `DELETE FROM USER_GUARDIAN_LINK WHERE user_id IN (SELECT user_id FROM USERS WHERE email = ?)`,
        //     [REGULAR_EMAIL]
        // );

        // Delete any existing user with this email
        await pool.execute(
            `DELETE FROM USERS WHERE email = ?`,
            [REGULAR_EMAIL]
        );

        // Insert fresh user
        const hashed = await bcrypt.hash(REGULAR_PASSWORD, 10);
        await pool.execute(
            `INSERT INTO USERS (email, password, accountType, isPremiumUser, scanCount, createdAt, updatedAt)
             VALUES (?, ?, 'User', FALSE, 0, NOW(), NOW())`,
            [REGULAR_EMAIL, hashed]
        );
        const [rows] = await pool.execute(
            `SELECT user_id FROM USERS WHERE email = ?`,
            [REGULAR_EMAIL]
        );
        regularUserId = rows[0].user_id;

        // Login to get token
        const loginRes = await request(app)
            .post('/api/auth/login')
            .send({ email: REGULAR_EMAIL, password: REGULAR_PASSWORD })
            .expect(200);
        expect(loginRes.body).to.have.property('token');
        userToken = loginRes.body.token;
    });

    after(async function () {
        // Cleanup OTPs
        await pool.execute(
            `DELETE FROM OTPS WHERE user_id = ?`,
            [regularUserId]
        );

        // Cleanup any scans created via the CRUD tests
        if (ocrScanId) {
            await pool.execute(
                `DELETE FROM OCR_SCANS WHERE ocr_id = ?`,
                [ocrScanId]
            );
        }
        if (objectScanId) {
            await pool.execute(
                `DELETE FROM OBJECT_SCANS WHERE scan_id = ?`,
                [objectScanId]
            );
        }

        // Cleanup any remaining scans (including those inserted in the GET-by-user test)
        await pool.execute(
            `DELETE FROM OCR_SCANS WHERE user_id = ?`,
            [regularUserId]
        );
        await pool.execute(
            `DELETE FROM OBJECT_SCANS WHERE user_id = ?`,
            [regularUserId]
        );

        // Delete the test user
        await pool.execute(
            `DELETE FROM USERS WHERE user_id = ?`,
            [regularUserId]
        );
    });

    // ─── Basic Profile Endpoints ──────────────────────────────────────────

    it('GET /api/user/dashboard → should return dashboard info', async function () {
        const res = await request(app)
            .get('/api/user/dashboard')
            .set('Authorization', `Bearer ${userToken}`)
            .expect(200);

        expect(res.body).to.have.property('message');
        expect(res.body).to.have.nested.property('user.user_id', regularUserId);
        expect(res.body).to.have.nested.property('user.email', REGULAR_EMAIL);
    });

    it('GET /api/user/profile → should return full profile', async function () {
        const res = await request(app)
            .get('/api/user/profile')
            .set('Authorization', `Bearer ${userToken}`)
            .expect(200);

        expect(res.body).to.have.property('user_id', regularUserId);
        expect(res.body).to.have.property('email', REGULAR_EMAIL);
        expect(res.body).to.have.property('accountType', 'User');
    });

    // ─── OCR CRUD ─────────────────────────────────────────────────────────────

    it('POST /api/user/ocr-scans → should create a new OCR scan', async function () {
        const payload = { recognizedText: 'Test OCR Text', text: 'OCR notes' };
        const res = await request(app)
            .post('/api/user/ocr-scans')
            .set('Authorization', `Bearer ${userToken}`)
            .send(payload)
            .expect(201);

        expect(res.body).to.have.property('message', 'OCR scan created.');
        expect(res.body).to.have.property('scan').that.is.an('object');
        const scan = res.body.scan;
        expect(scan).to.have.property('scanId').that.is.a('number');
        expect(scan).to.include({ recognizedText: payload.recognizedText, text: payload.text });
        ocrScanId = scan.scanId;
    });

    it('GET /api/user/scans → should list the OCR scan', async function () {
        const res = await request(app)
            .get('/api/user/scans')
            .set('Authorization', `Bearer ${userToken}`)
            .expect(200);

        expect(res.body).to.be.an('array').that.is.not.empty;
        const found = res.body.find(r => r.type === 'Text' && r.scanId === ocrScanId);
        expect(found).to.exist;
    });

    it('GET /api/user/scans/:scanId → should return OCR scan details', async function () {
        const [dbRows] = await pool.execute(
            `SELECT recognizedText AS name, text FROM OCR_SCANS WHERE ocr_id = ?`,
            [ocrScanId]
        );
        const expected = dbRows[0];

        const res = await request(app)
            .get(`/api/user/scans/${ocrScanId}`)
            .set('Authorization', `Bearer ${userToken}`)
            .expect(200);

        expect(res.body).to.include({ type: 'Text', scanId: ocrScanId, name: expected.name, text: expected.text });
        expect(res.body).to.have.keys('type','scanId','name','text','dateTime','createdAt','updatedAt');
    });

    it('PUT /api/user/scans/:scanId → should update OCR scan', async function () {
        const updated = { type: 'Text', name: 'Updated OCR', text: 'Updated notes' };
        await request(app)
            .put(`/api/user/scans/${ocrScanId}`)
            .set('Authorization', `Bearer ${userToken}`)
            .send(updated)
            .expect(200);

        const [rows] = await pool.execute(
            `SELECT recognizedText, text FROM OCR_SCANS WHERE ocr_id = ?`,
            [ocrScanId]
        );
        expect(rows[0].recognizedText).to.equal(updated.name);
        expect(rows[0].text).to.equal(updated.text);
    });

    it('DELETE /api/user/scans/:scanId → should delete OCR scan', async function () {
        await request(app)
            .delete(`/api/user/scans/${ocrScanId}`)
            .set('Authorization', `Bearer ${userToken}`)
            .expect(200);

        const [rows] = await pool.execute(
            `SELECT * FROM OCR_SCANS WHERE ocr_id = ?`,
            [ocrScanId]
        );
        expect(rows).to.be.empty;
        ocrScanId = null;
    });

    // ─── OBJECT CRUD ──────────────────────────────────────────────────────────

    it('POST /api/user/object-scans → should create a new Object scan', async function () {
        const payload = { recognizedObjects: 'Cat,Dog', text: 'Obj notes' };
        const res = await request(app)
            .post('/api/user/object-scans')
            .set('Authorization', `Bearer ${userToken}`)
            .send(payload)
            .expect(201);

        expect(res.body).to.have.property('message', 'Object scan created.');
        const scan = res.body.scan;
        expect(scan).to.include({ recognizedObjects: payload.recognizedObjects, text: payload.text });
        objectScanId = scan.scanId;
    });

    it('GET /api/user/scans → should list the Object scan', async function () {
        const res = await request(app)
            .get('/api/user/scans')
            .set('Authorization', `Bearer ${userToken}`)
            .expect(200);

        const found = res.body.find(r => r.type === 'Object' && r.scanId === objectScanId);
        expect(found).to.exist;
    });

    it('GET /api/user/scans/:scanId → should return Object scan details', async function () {
        const [dbRows] = await pool.execute(
            `SELECT recognizedObjects AS name, text FROM OBJECT_SCANS WHERE scan_id = ?`,
            [objectScanId]
        );
        const expected = dbRows[0];

        const res = await request(app)
            .get(`/api/user/scans/${objectScanId}`)
            .set('Authorization', `Bearer ${userToken}`)
            .expect(200);

        expect(res.body).to.include({ type: 'Object', scanId: objectScanId, name: expected.name, text: expected.text });
    });

    it('PUT /api/user/scans/:scanId → should update Object scan', async function () {
        const updated = { type: 'Object', name: 'Cat,Dog,Fox', text: 'Updated obj' };
        await request(app)
            .put(`/api/user/scans/${objectScanId}`)
            .set('Authorization', `Bearer ${userToken}`)
            .send(updated)
            .expect(200);

        const [rows] = await pool.execute(
            `SELECT recognizedObjects, text FROM OBJECT_SCANS WHERE scan_id = ?`,
            [objectScanId]
        );
        expect(rows[0].recognizedObjects).to.equal(updated.name);
        expect(rows[0].text).to.equal(updated.text);
    });

    it('DELETE /api/user/scans/:scanId → should delete Object scan', async function () {
        await request(app)
            .delete(`/api/user/scans/${objectScanId}`)
            .set('Authorization', `Bearer ${userToken}`)
            .expect(200);

        const [rows] = await pool.execute(
            `SELECT * FROM OBJECT_SCANS WHERE scan_id = ?`,
            [objectScanId]
        );
        expect(rows).to.be.empty;
        objectScanId = null;
    });

    // ─── New: GET scans by user ─────────────────────────────────────────────────

    it('GET /api/user/scans/user?user_id=<id> → should retrieve scans by user', async function () {
        // Recreate two scans for test
        await pool.execute(
            `INSERT INTO OCR_SCANS (user_id, recognizedText, text, dateTime, createdAt, updatedAt)
             VALUES (?, 'Foo', 'Bar', NOW(), NOW(), NOW())`,
            [regularUserId]
        );
        await pool.execute(
            `INSERT INTO OBJECT_SCANS (user_id, recognizedObjects, text, createdAt, updatedAt)
             VALUES (?, 'X', 'Y', NOW(), NOW())`,
            [regularUserId]
        );

        const [ocrRow] = await pool.execute(
            `SELECT MAX(ocr_id) AS id FROM OCR_SCANS WHERE user_id = ?`,
            [regularUserId]
        );
        const [objRow] = await pool.execute(
            `SELECT MAX(scan_id) AS id FROM OBJECT_SCANS WHERE user_id = ?`,
            [regularUserId]
        );
        const oId = ocrRow[0].id;
        const sId = objRow[0].id;

        const res = await request(app)
            .get(`/api/user/guardian/scans/user?user_id=${regularUserId}`)
            .set('Authorization', `Bearer ${userToken}`)
            .expect(200);

        expect(res.body).to.be.an('array');
        const foundOCR = res.body.find(r => r.type === 'Text' && r.scanId === oId);
        const foundObj = res.body.find(r => r.type === 'Object' && r.scanId === sId);
        expect(foundOCR).to.exist;
        expect(foundObj).to.exist;
    });

    // ─── Negative auth checks ──────────────────────────────────────────────────

    it('GET /api/user/dashboard without token → 401', async function () {
        return request(app)
            .get('/api/user/dashboard')
            .expect(401);
    });

    it('GET /api/user/dashboard with invalid token → 401', async function () {
        return request(app)
            .get('/api/user/dashboard')
            .set('Authorization', 'Bearer invalid')
            .expect(401);
    });

});
