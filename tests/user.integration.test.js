// tests/user.integration.test.js

const chai = require('chai');
const expect = chai.expect;
const request = require('supertest');
const bcrypt = require('bcryptjs');
const pool = require('../db');
const app = require('../index');

describe('User Integration Tests)', function () {
    this.timeout(20000);

    const REGULAR_EMAIL = 'regular.user@test.com';
    const REGULAR_PASSWORD = 'RegularPassword123!';
    let regularUserId;
    let userToken;
    let ocrScanId;
    let objectScanId;

    before(async function () {
        // 1) Clean up any existing OTPs & the user itself
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
             VALUES (?, ?, 'User', FALSE, 0, NOW(), NOW())`,
            [REGULAR_EMAIL, hashed]
        );
        const [rows] = await pool.execute(
            `SELECT user_id FROM USERS WHERE email = ?`,
            [REGULAR_EMAIL]
        );
        regularUserId = rows[0].user_id;

        // 3) Sign in via the real /api/auth/login to get a JWT
        const loginRes = await request(app)
            .post('/api/auth/login')
            .send({ email: REGULAR_EMAIL, password: REGULAR_PASSWORD })
            .expect(200);

        expect(loginRes.body).to.have.property('token');
        userToken = loginRes.body.token;
    });

    after(async function () {
        // 1) Delete any remaining sessions / OTPs
        await pool.execute(
            `DELETE FROM OTPS 
       WHERE user_id = ?`,
            [regularUserId]
        );

        // 2) Delete any leftover OCR scan
        if (ocrScanId) {
            await pool.execute(`DELETE FROM OCR_SCANS WHERE ocr_id = ?`, [ocrScanId]);
        }
        // 3) Delete any leftover Object scan
        if (objectScanId) {
            await pool.execute(`DELETE FROM OBJECT_SCANS WHERE scan_id = ?`, [objectScanId]);
        }

        // 4) Delete the user itself
        await pool.execute(`DELETE FROM USERS WHERE user_id = ?`, [regularUserId]);
    });

    //
    // ──────── OCR –– CRUD TESTS ─────────────────────────────────────────────
    //

    it('POST /api/user/ocr-scans → should create a new OCR scan', async function () {
        const payload = {
            recognizedText: 'Test OCR Text',
            text: 'OCR additional notes'
        };
        const res = await request(app)
            .post('/api/user/ocr-scans')
            .set('Authorization', 'Bearer ' + userToken)
            .send(payload)
            .expect(201);

        expect(res.body).to.have.property('message', 'OCR scan created successfully.');
        expect(res.body).to.have.property('scan').that.is.an('object');
        const scan = res.body.scan;
        expect(scan).to.have.property('scanId').that.is.a('number');
        expect(scan).to.include({
            recognizedText: payload.recognizedText,
            text: payload.text
        });
        ocrScanId = scan.scanId;
    });

    it('GET /api/user/scans → should list exactly that OCR scan', async function () {
        const res = await request(app)
            .get('/api/user/scans')
            .set('Authorization', 'Bearer ' + userToken)
            .expect(200);

        expect(res.body).to.be.an('array').with.lengthOf(1);
        const foundOCR = res.body.find(r => r.type === 'Text' && r.scanId === ocrScanId);
        expect(foundOCR).to.exist;
        // No Object entries at this point
    });

    it('GET /api/user/scans/:scanId → should return OCR scan details', async function () {
        // Fetch expected from DB
        const [dbRows] = await pool.execute(
            `SELECT recognizedText AS name, text
             FROM OCR_SCANS
             WHERE ocr_id = ?`,
            [ocrScanId]
        );
        expect(dbRows.length).to.equal(1);
        const expectedName = dbRows[0].name;
        const expectedText = dbRows[0].text;

        const res = await request(app)
            .get(`/api/user/scans/${ocrScanId}`)
            .set('Authorization', 'Bearer ' + userToken)
            .expect(200);

        expect(res.body).to.include({
            type: 'Text',
            scanId: ocrScanId,
            name: expectedName,
            text: expectedText
        });
        expect(res.body).to.have.property('dateTime');
        expect(res.body).to.have.property('createdAt');
        expect(res.body).to.have.property('updatedAt');
    });

    it('PUT /api/user/scans/:scanId → should update OCR scan', async function () {
        const updated = {
            type: 'Text',
            name: 'Updated OCR Text',
            text: 'Updated OCR notes'
        };
        await request(app)
            .put(`/api/user/scans/${ocrScanId}`)
            .set('Authorization', 'Bearer ' + userToken)
            .send(updated)
            .expect(200);

        // Verify in the database that the OCR row was updated
        const [rows] = await pool.execute(
            `SELECT recognizedText, text
             FROM OCR_SCANS
             WHERE ocr_id = ?`,
            [ocrScanId]
        );
        expect(rows.length).to.equal(1);
        expect(rows[0].recognizedText).to.equal(updated.name);
        expect(rows[0].text).to.equal(updated.text);
    });

    it('DELETE /api/user/scans/:scanId → should delete OCR scan', async function () {
        await request(app)
            .delete(`/api/user/scans/${ocrScanId}`)
            .set('Authorization', 'Bearer ' + userToken)
            .expect(200);

        // Verify removal from OCR_SCANS
        const [rows] = await pool.execute(
            `SELECT * FROM OCR_SCANS WHERE ocr_id = ?`,
            [ocrScanId]
        );
        expect(rows.length).to.equal(0);
        ocrScanId = null;
    });

    //
    // ──────── OBJECT –– CRUD TESTS ─────────────────────────────────────────
    //

    it('POST /api/user/object-scans → should create a new Object scan', async function () {
        const payload = {
            recognizedObjects: 'Cat, Dog',
            text: 'Object scan notes'
        };
        const res = await request(app)
            .post('/api/user/object-scans')
            .set('Authorization', 'Bearer ' + userToken)
            .send(payload)
            .expect(201);

        expect(res.body).to.have.property('message', 'Object scan created successfully.');
        expect(res.body).to.have.property('scan').that.is.an('object');
        const scan = res.body.scan;
        expect(scan).to.have.property('scanId').that.is.a('number');
        expect(scan).to.include({
            recognizedObjects: payload.recognizedObjects,
            text: payload.text
        });
        objectScanId = scan.scanId;
    });

    it('GET /api/user/scans → should list exactly that Object scan', async function () {
        const res = await request(app)
            .get('/api/user/scans')
            .set('Authorization', 'Bearer ' + userToken)
            .expect(200);

        expect(res.body).to.be.an('array').with.lengthOf(1);
        const foundObj = res.body.find(r => r.type === 'Object' && r.scanId === objectScanId);
        expect(foundObj).to.exist;
        // No OCR entries at this point
    });

    it('GET /api/user/scans/:scanId → should return Object scan details', async function () {
        // Fetch expected from DB
        const [dbRows] = await pool.execute(
            `SELECT recognizedObjects AS name, text
             FROM OBJECT_SCANS
             WHERE scan_id = ?`,
            [objectScanId]
        );
        expect(dbRows.length).to.equal(1);
        const expectedName = dbRows[0].name;
        const expectedText = dbRows[0].text;

        const res = await request(app)
            .get(`/api/user/scans/${objectScanId}`)
            .set('Authorization', 'Bearer ' + userToken)
            .expect(200);

        expect(res.body).to.include({
            type: 'Object',
            scanId: objectScanId,
            name: expectedName,
            text: expectedText
        });
        expect(res.body).to.have.property('createdAt');
        expect(res.body).to.have.property('updatedAt');
    });

    it('PUT /api/user/scans/:scanId → should update Object scan', async function () {
        const updated = {
            type: 'Object',
            name: 'Cat, Dog, Fox',
            text: 'Updated object notes'
        };
        await request(app)
            .put(`/api/user/scans/${objectScanId}`)
            .set('Authorization', 'Bearer ' + userToken)
            .send(updated)
            .expect(200);

        // Verify in the database that the Object row was updated
        const [rows] = await pool.execute(
            `SELECT recognizedObjects, text
             FROM OBJECT_SCANS
             WHERE scan_id = ?`,
            [objectScanId]
        );
        expect(rows.length).to.equal(1);
        expect(rows[0].recognizedObjects).to.equal(updated.name);
        expect(rows[0].text).to.equal(updated.text);
    });

    it('DELETE /api/user/scans/:scanId → should delete Object scan', async function () {
        await request(app)
            .delete(`/api/user/scans/${objectScanId}`)
            .set('Authorization', 'Bearer ' + userToken)
            .expect(200);

        // Verify removal from OBJECT_SCANS
        const [rows] = await pool.execute(
            `SELECT * FROM OBJECT_SCANS WHERE scan_id = ?`,
            [objectScanId]
        );
        expect(rows.length).to.equal(0);
        objectScanId = null;
    });

    //
    // ──────── NEGATIVE (TOKEN) CHECKS ───────────────────────────────────────────────
    //

    it('GET /api/user/dashboard with missing token → should return 401', async function () {
        await request(app)
            .get('/api/user/dashboard')
            // no Authorization header
            .expect(401);
    });

    it('GET /api/user/dashboard with invalid token → should return 401', async function () {
        await request(app)
            .get('/api/user/dashboard')
            .set('Authorization', 'Bearer invalid.token')
            .expect(401);
    });
});
