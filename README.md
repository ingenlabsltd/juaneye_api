# 🚀 JuanEye API Overview

JuanEye backend routes.

---

## 📋 Quick Reference

| Method | Endpoint                              | Purpose                        |
|--------|---------------------------------------|--------------------------------|
| POST   | `/api/auth/login`                     | Login                          |
| POST   | `/api/auth/forgot-password`           | Request OTP                    |
| POST   | `/api/auth/reset-password`            | Reset Password                 |
| GET    | `/api/user/dashboard`                 | User Dashboard                 |
| GET    | `/api/user/profile`                   | User Profile                   |
| POST   | `/api/user/ocr-scans`                 | Create OCR Scan                |
| POST   | `/api/user/object-scans`              | Create Object Scan             |
| GET    | `/api/user/scans`                     | List All Scans                 |
| GET    | `/api/user/scans/:scanId`             | Get Single Scan                |
| PUT    | `/api/user/scans/:scanId`             | Update Scan                    |
| DELETE | `/api/user/scans/:scanId`             | Delete Scan                    |
| GET    | `/api/dashboard`                      | Generic Dashboard              |
| GET    | `/api/admin/dashboard`                | Admin Dashboard                |
| GET    | `/api/admin/users?page=<n>&limit=<m>` | List Users (Paginated)         |
| POST   | `/api/admin/users`                    | Create User                    |
| GET    | `/api/admin/users/:userId`            | Get Single User                |
| PUT    | `/api/admin/users/:userId`            | Update User                    |
| DELETE | `/api/admin/users/:userId`            | Delete User                    |
| GET    | `/api/admin/users/:userId/scans`      | List User’s Scans              |
| PUT    | `/api/admin/scans/:scanId`            | Update Scan (Admin)            |
| DELETE | `/api/admin/scans/:scanId`            | Delete Scan (Admin)            |
| GET    | `/api/admin/report?date=YYYY-MM-DD`   | Daily User Report              |

---

## 🔐 Authentication (Public)

_No token required_

1. **POST** `/api/auth/login`  
   🔑 **Login**  
   - **Purpose:** Sign in with email/password.  
   - **You send:**
     ```json
     {
       "email": "user@example.com",
       "password": "YourPassword123!"
     }
     ```
   - **You get (200):**  
     ```json
     { "token": "<JWT_TOKEN>" }
     ```  
   - **Error:** 401 if credentials are invalid.

2. **POST** `/api/auth/forgot-password`  
   📩 **Request OTP**  
   - **Purpose:** Request a one-time code (OTP) for password reset.  
   - **You send:**
     ```json
     { "email": "user@example.com" }
     ```
   - **You get (200):**  
     ```json
     { "message": "If the email exists, an OTP has been sent." }
     ```  
   - *Always returns 200 (for security).*

3. **POST** `/api/auth/reset-password`  
   🔄 **Reset Password**  
   - **Purpose:** Submit OTP + new password to update your account.  
   - **You send:**
     ```json
     {
       "email": "user@example.com",
       "codeValue": "123456",
       "newPassword": "NewSecurePass!45"
     }
     ```
   - **You get (200):**  
     ```json
     { "message": "Password has been reset successfully." }
     ```  
   - **Error:** 400 if OTP is invalid or expired.

---

## 👤 User (Requires JWT)

_Place header: `Authorization: Bearer <token>`_

1. **GET** `/api/user/dashboard`  
   📊 **User Dashboard**  
   - **What it does:** Show your dashboard summary (greeting + basic stats).  
   - **You get (200):**  
     ```json
     {
       "message": "Welcome to your dashboard, user@example.com!",
       "user": {
         "user_id": 123,
         "email": "user@example.com",
         "accountType": "User",
         "scanCount": 10,
         "isPremiumUser": false
       }
     }
     ```
   - **Error:** 401 if token missing/invalid.

2. **GET** `/api/user/profile`  
   📝 **User Profile**  
   - **What it does:** Fetch your complete profile (email, device UUID, phone, timestamps, etc.).  
   - **You get (200):**  
     ```json
     {
       "user_id": 123,
       "email": "user@example.com",
       "accountType": "User",
       "isPremiumUser": 0,
       "scanCount": 10,
       "deviceUuid": "abc-123-uuid",
       "phone": "555-123-4567",
       "createdAt": "2025-05-01T12:34:56.000Z",
       "updatedAt": "2025-05-10T08:20:00.000Z"
     }
     ```
   - **Error:** 401 if token missing/invalid.

3. **POST** `/api/user/ocr-scans`  
   🖋️ **Create OCR Scan**  
   - **What it does:** Create a new OCR scan (recognized text + notes).  
   - **You send:**
     ```json
     {
       "recognizedText": "Example text",
       "text": "Any additional notes"
     }
     ```
   - **You get (201):**
     ```json
     {
       "message": "OCR scan created successfully.",
       "scan": {
         "scanId": 42,
         "recognizedText": "Example text",
         "text": "Any additional notes"
       }
     }
     ```
   - **Errors:**  
     - 400 if fields missing/invalid.  
     - 401 if token missing/invalid.

4. **POST** `/api/user/object-scans`  
   🖼️ **Create Object Scan**  
   - **What it does:** Create a new Object scan (recognized objects + notes).  
   - **You send:**
     ```json
     {
       "recognizedObjects": "Cat, Dog",
       "text": "Additional context"
     }
     ```
   - **You get (201):**
     ```json
     {
       "message": "Object scan created successfully.",
       "scan": {
         "scanId": 57,
         "recognizedObjects": "Cat, Dog",
         "text": "Additional context"
       }
     }
     ```
   - **Errors:**  
     - 400 if fields missing/invalid.  
     - 401 if token missing/invalid.

5. **GET** `/api/user/scans`  
   📚 **List All Scans**  
   - **What it does:** List all your scans (OCR & Object), newest first.  
   - **You get (200):**
     ```json
     [
       {
         "scanId": 57,
         "name": "Cat, Dog",
         "text": "Additional context",
         "type": "Object",
         "createdAt": "2025-06-05T10:00:00.000Z"
       },
       {
         "scanId": 42,
         "name": "Example text",
         "text": "Any additional notes",
         "type": "Text",
         "createdAt": "2025-06-05T09:30:00.000Z"
       }
     ]
     ```
   - **Error:** 401 if token missing/invalid.

6. **GET** `/api/user/scans/:scanId`  
   🔍 **Get Single Scan**  
   - **What it does:** Get details for one scan (OCR or Object).  
   - **Path Param:** `scanId` (e.g., `/api/user/scans/42`)  
   - **You get (OCR):**
     ```json
     {
       "type": "Text",
       "scanId": 42,
       "name": "Example text",
       "text": "Any additional notes",
       "dateTime": "2025-06-05T09:30:00.000Z",
       "createdAt": "2025-06-05T09:30:00.000Z",
       "updatedAt": "2025-06-05T09:45:00.000Z"
     }
     ```
   - **You get (Object):**
     ```json
     {
       "type": "Object",
       "scanId": 57,
       "name": "Cat, Dog",
       "text": "Additional context",
       "createdAt": "2025-06-05T10:00:00.000Z",
       "updatedAt": "2025-06-05T10:05:00.000Z"
     }
     ```
   - **Errors:**  
     - 401 if token missing/invalid.  
     - 404 if scan not found or not yours.

7. **PUT** `/api/user/scans/:scanId`  
   ✏️ **Update Scan**  
   - **What it does:** Update an existing scan (OCR or Object).  
   - **Path Param:** `scanId`  
   - **You send (OCR):**
     ```json
     {
       "type": "Text",
       "name": "Updated recognized text",
       "text": "Updated notes"
     }
     ```
   - **You send (Object):**
     ```json
     {
       "type": "Object",
       "name": "Cat, Dog, Fox",
       "text": "Updated notes"
     }
     ```
   - **You get (200):**  
     - OCR: `{ "message": "OCR scan updated successfully." }`  
     - Object: `{ "message": "Object scan updated successfully." }`  
   - **Errors:**  
     - 400 if invalid payload.  
     - 401 if token missing/invalid.  
     - 404 if scan not found or not yours.

8. **DELETE** `/api/user/scans/:scanId`  
   🗑️ **Delete Scan**  
   - **What it does:** Permanently delete a scan (OCR or Object).  
   - **Path Param:** `scanId`  
   - **You get (200):**  
     - OCR: `{ "message": "OCR scan deleted successfully." }`  
     - Object: `{ "message": "Object scan deleted successfully." }`  
   - **Errors:**  
     - 401 if token missing/invalid.  
     - 404 if scan not found or not yours.

---

## ⚙️ Admin (Requires Admin JWT)

_Non-admins get 403 Forbidden_

1. **GET** `/api/admin/dashboard`  
   📈 **Admin Dashboard**  
   - **What it does:** View system stats (online users, totals, free/premium counts, last 7 days signups).  
   - **You get (200):**
     ```json
     {
       "onlineUsers": 123,
       "totalUsers": 500,
       "freeUsers": 380,
       "premiumUsers": 120,
       "newSignupsLast7Days": [
         { "date": "2025-05-29", "count": 5 },
         { "date": "2025-05-30", "count": 8 },
         { "date": "2025-05-31", "count": 12 },
         { "date": "2025-06-01", "count": 10 },
         { "date": "2025-06-02", "count": 7 },
         { "date": "2025-06-03", "count": 9 },
         { "date": "2025-06-04", "count": 11 }
       ]
     }
     ```
   - **Errors:**  
     - 401 if token missing/invalid.  
     - 403 if non-admin.

2. **GET** `/api/admin/users?page=<n>&limit=<m>`  
   📋 **List Users**  
   - **What it does:** List all users (paginated).  
   - **Query Params:** `page` (number), `limit` (number)  
   - **You get (200):**
     ```json
     {
       "total": 304,
       "users": [
         {
           "user_id": 15,
           "email": "alice@example.com",
           "userType": "User",
           "subscriptionType": "Free",
           "scanCount": 12,
           "guardianModeAccess": "No"
         },
         {
           "user_id": 14,
           "email": "bob@gmail.com",
           "userType": "Guardian",
           "subscriptionType": "Premium",
           "scanCount": 0,
           "guardianModeAccess": "Yes"
         }
         // …up to `limit` entries…
       ]
     }
     ```
   - **Errors:**  
     - 401 if token missing/invalid.  
     - 403 if non-admin.  
     - 400 if `page`/`limit` invalid.

3. **POST** `/api/admin/users`  
   ➕ **Create User**  
   - **What it does:** Create a new user account.  
   - **You send:**
     ```json
     {
       "email": "new.user@example.com",
       "password": "StrongPass!23",
       "accountType": "User",
       "isPremiumUser": false,
       "scanCount": 5,
       "phone": "123-456-7890",
       "deviceUuid": "device-uuid-xyz"
     }
     ```
   - **You get (201):**
     ```json
     {
       "user": {
         "user_id": 305,
         "email": "new.user@example.com",
         "userType": "User",
         "subscriptionType": "Free",
         "scanCount": 5,
         "guardianModeAccess": "No"
       }
     }
     ```
   - **Errors:**  
     - 401 if token missing/invalid.  
     - 403 if non-admin.  
     - 400 if missing/invalid fields.

4. **GET** `/api/admin/users/:userId`  
   👀 **Get Single User**  
   - **What it does:** Fetch one user’s details.  
   - **Path Param:** `userId`  
   - **You get (200):**
     ```json
     {
       "user_id": 305,
       "email": "new.user@example.com",
       "userType": "User",
       "subscriptionType": "Free",
       "scanCount": 5,
       "guardianModeAccess": "No",
       "phone": "123-456-7890",
       "deviceUuid": "device-uuid-xyz",
       "createdAt": "2025-06-01T08:00:00.000Z",
       "updatedAt": "2025-06-01T08:00:00.000Z"
     }
     ```
   - **Errors:**  
     - 401 if token missing/invalid.  
     - 403 if non-admin.  
     - 404 if user not found.

5. **PUT** `/api/admin/users/:userId`  
   ✏️ **Update User**  
   - **What it does:** Update one user’s data.  
   - **Path Param:** `userId`  
   - **You send:**
     ```json
     {
       "email": "updated@example.com",
       "accountType": "Guardian",
       "isPremiumUser": true,
       "scanCount": 10,
       "phone": "987-654-3210",
       "deviceUuid": "new-device-uuid"
     }
     ```
   - **You get (200):**  
     ```json
     { "message": "User updated successfully." }
     ```
   - **Errors:**  
     - 401 if token missing/invalid.  
     - 403 if non-admin.  
     - 404 if user not found.  
     - 400 if invalid data.

6. **DELETE** `/api/admin/users/:userId`  
   🗑️ **Delete User**  
   - **What it does:** Delete a user + related data.  
   - **Path Param:** `userId`  
   - **You get (200):**  
     ```json
     { "message": "User and associated data deleted successfully." }
     ```
   - **Errors:**  
     - 401 if token missing/invalid.  
     - 403 if non-admin.  
     - 404 if user not found.

7. **GET** `/api/admin/users/:userId/scans`  
   📂 **List User’s Scans**  
   - **What it does:** List all scans for a specific user.  
   - **Path Param:** `userId`  
   - **You get (200):**
     ```json
     [
       {
         "scanId": 57,
         "name": "Cat, Dog",
         "type": "Object",
         "photo": "img234.jpg",
         "audio": null
       },
       {
         "scanId": 42,
         "name": "Example text",
         "type": "Text",
         "photo": null,
         "audio": "audio123.mp3"
       }
       // …other scans…
     ]
     ```
   - **Errors:**  
     - 401 if token missing/invalid.  
     - 403 if non-admin.  
     - 404 if user not found.

8. **PUT** `/api/admin/scans/:scanId`  
   ✏️ **Update Scan (Admin)**  
   - **What it does:** Update a scan on behalf of any user.  
   - **Path Param:** `scanId`  
   - **You send (OCR):**
     ```json
     {
       "type": "Text",
       "name": "Corrected text",
       "text": "Corrected notes"
     }
     ```
   - **You get (200):**  
     ```json
     { "message": "OCR scan updated successfully." }
     ```
     or
     ```json
     { "message": "Object scan updated successfully." }
     ```
   - **Errors:**  
     - 401 if token missing/invalid.  
     - 403 if non-admin.  
     - 404 if scan not found or belongs to another user.  
     - 400 if invalid payload.

9. **DELETE** `/api/admin/scans/:scanId`  
   🗑️ **Delete Scan (Admin)**  
   - **What it does:** Permanently delete a scan (OCR or Object).  
   - **Path Param:** `scanId`  
   - **You get (200):**  
     ```json
     { "message": "OCR scan deleted successfully." }
     ```
     or
     ```json
     { "message": "Object scan deleted successfully." }
     ```
   - **Errors:**  
     - 401 if token missing/invalid.  
     - 403 if non-admin.  
     - 404 if scan not found.

10. **GET** `/api/admin/report?date=YYYY-MM-DD`  
    📑 **Daily User Report**  
    - **What it does:** List all users created on a specific date.  
    - **Query Param:** `date=2025-06-03`  
    - **You get (200):**
      ```json
      {
        "date": "2025-06-03",
        "users": [
          {
            "user_id": 98,
            "email": "newbie@example.com",
            "accountType": "User",
            "createdAt": "2025-06-03T08:12:00.000Z"
          },
          {
            "user_id": 99,
            "email": "guardian2@example.com",
            "accountType": "Guardian",
            "createdAt": "2025-06-03T11:45:00.000Z"
          }
          // …others…
        ]
      }
      ```
    - **Errors:**  
      - 401 if token missing/invalid.  
      - 403 if non-admin.  
      - 400 if `date` missing or invalid format.

---

### 📝 Notes

- **All “User” routes** require a valid JWT.  
- **All “Admin” routes** require a valid JWT _and_ `accountType = "Admin"`.  
- If your token is missing/invalid, you’ll get **401 Unauthorized**.  
- If you’re not an Admin but try an Admin route, you’ll get **403 Forbidden**.  
- Format date queries as `YYYY-MM-DD` (e.g., `2025-06-03`).

Happy integrating! 🎉  
