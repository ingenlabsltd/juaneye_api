# 🚀 JuanEye API Overview

JuanEye backend routes.

---

## 📋 Quick Reference

| Method | Endpoint                              | Purpose                        |
|--------|---------------------------------------|--------------------------------|
| POST   | `/api/auth/login`                     | Login                          |
| POST   | `/api/auth/forgot-password`           | Request OTP                    |
| POST   | `/api/auth/reset-password`            | Reset Password                 |
| POST   | `/api/auth/signup`                    | User Signup                    |
| POST   | `/api/auth/verify-login`              | Verify Login OTP               |
| POST   | `/api/auth/resend-otp`                | Resend OTP                     |
| GET    | `/api/user/dashboard`                 | User Dashboard                 |
| GET    | `/api/user/profile`                   | User Profile                   |
| POST   | `/api/user/ocr-scans`                 | Create OCR Scan                |
| POST   | `/api/user/object-scans`              | Create Object Scan             |
| GET    | `/api/user/scans`                     | List All Scans                 |
| GET    | `/api/user/scans/:scanId`             | Get Single Scan                |
| PUT    | `/api/user/scans/:scanId`             | Update Scan                    |
| DELETE | `/api/user/scans/:scanId`             | Delete Scan                    |
| POST   | `/api/user/photo-upload`              | Upload Photo for LLM           |
| POST   | `/api/user/llm-ask-question`          | Ask LLM Question               |
| GET    | `/api/user/get-guardians`             | Get User's Guardians           |
| DELETE | `/api/user/remove-guardian/:guardianId` | Remove a Guardian              |
| POST   | `/api/user/guardian/bind-request`     | Request Guardian Binding       |
| POST   | `/api/user/guardian/bind-confirm`     | Confirm Guardian Binding       |
| GET    | `/api/user/guardian/bound-users`      | List Bound Users               |
| GET    | `/api/user/guardian/scan-stats`       | Get Scan Statistics            |
| GET    | `/api/user/guardian/all-scans/user`   | Get User's Scans (Guardian)    |
| POST   | `/api/user/guardian/llm-ask-question` | Ask LLM Question (Guardian)    |
| GET    | `/api/user/guardian/:conversationId/image` | Get Conversation Image         |
| GET    | `/api/user/guardian/conversation/:conversationId/history` | Get Conversation History     |
| GET    | `/api/user/premium/status`            | Get Premium Status             |
| POST   | `/api/user/premium/purchase`          | Purchase Premium               |
| GET    | `/api/admin/dashboard`                | Admin Dashboard                |
| GET    | `/api/admin/users?page=<n>&limit=<m>` | List Users (Paginated)         |
| POST   | `/api/admin/users`                    | Create User                    |
| GET    | `/api/admin/users/:userId`            | Get Single User                |
| PUT    | `/api/admin/users/:userId`            | Update User                    |
| DELETE | `/api/admin/users/:userId`            | Delete User                    |
| GET    | `/api/admin/users/:userId/scans`      | List User's Scans              |
| GET    | `/api/admin/users/:userId/transactions` | Get User's Transactions        |
| PUT    | `/api/admin/users/:userId/make-premium` | Make User Premium              |
| PUT    | `/api/admin/users/:userId/remove-premium` | Remove User Premium            |
| GET    | `/api/admin/users/:userId/guardians`  | Get User's Guardians (Admin)   |
| POST   | `/api/admin/users/:userId/guardians`  | Bind Guardian (Admin)          |
| DELETE | `/api/admin/users/:userId/guardians/:guardianId` | Unbind Guardian (Admin)        |
| GET    | `/api/admin/users/:userId/activity`   | Get User Activity              |
| GET    | `/api/admin/scans/:conversationId/images` | Get Conversation Images (Admin)|
| GET    | `/api/admin/conversations/:conversationId/history` | Get Conversation History (Admin)|
| PUT    | `/api/admin/scans/:scanId`            | Update Scan (Admin)            |
| DELETE | `/api/admin/scans/:scanId`            | Delete Scan (Admin)            |
| GET    | `/api/admin/report?date=YYYY-MM-DD`   | Daily User Report              |
| GET    | `/api/admin/audit-trail`              | Get Audit Trail                |
| GET    | `/api/admin/guardians`                | List All Guardians             |
| GET    | `/api/admin/guardians/:guardianId/bound-users` | Get Guardian's Bound Users   |

---

## 🔐 Authentication (Public)

_No token required_

1. **POST** `/api/auth/login`  
   🔑 **Login**
    - **Purpose:** Sign in with email/password.
    - **Request:**
      ```json
      {
        "email": "user@example.com",
        "password": "YourPassword123!"
      }
      ```
    - **Response (200):**
      ```json
      { "token": "<JWT_TOKEN>" }
      ```  
    - **Error:** 401 if credentials are invalid.

2. **POST** `/api/auth/forgot-password`  
   📩 **Request OTP**
    - **Purpose:** Request a one-time code (OTP) for password reset.
    - **Request:**
      ```json
      { "email": "user@example.com" }
      ```
    - **Response (200):**
      ```json
      { "message": "If the email exists, an OTP has been sent." }
      ```  

3. **POST** `/api/auth/reset-password`  
   🔄 **Reset Password**
    - **Purpose:** Submit OTP + new password to update your account.
    - **Request:**
      ```json
      {
        "email": "user@example.com",
        "codeValue": "123456",
        "newPassword": "NewSecurePass!45"
      }
      ```
    - **Response (200):**
      ```json
      { "message": "Password has been reset successfully." }
      ```  
    - **Error:** 400 if OTP is invalid or expired.

4. **POST** `/api/auth/signup`
   📝 **User Signup**
    - **Purpose:** Register a new user account.
    - **Request:**
      ```json
      {
        "email": "newuser@example.com",
        "password": "NewSecurePassword123!",
        "accountType": "User"
      }
      ```
    - **Response (201):**
      ```json
      {
        "message": "Signup successful",
        "userId": 124,
        "token": "<JWT_TOKEN>"
      }
      ```

5. **POST** `/api/auth/verify-login`
   🔐 **Verify Login OTP**
    - **Purpose:** Submit OTP received after login to get a JWT.
    - **Request:**
      ```json
      {
        "email": "user@example.com",
        "codeValue": "123456"
      }
      ```
    - **Response (200):**
      ```json
      { "token": "<JWT_TOKEN>" }
      ```

6. **POST** `/api/auth/resend-otp`
   🔄 **Resend OTP**
    - **Purpose:** Request a new OTP, invalidating the previous one.
    - **Request:**
      ```json
      { "email": "user@example.com" }
      ```
    - **Response (200):**
      ```json
      { "message": "A new OTP has been sent to your email." }
      ```

---

## 👤 User (Requires JWT)

_Header: `Authorization: Bearer <token>`_

### 📄 Basic User Endpoints

1. **GET** `/api/user/dashboard`  
   📊 **User Dashboard**
    - **Response (200):**
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

2. **GET** `/api/user/profile`  
   📝 **User Profile**
    - **Response (200):**
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

### 🔍 Scan Management

3. **POST** `/api/user/ocr-scans`  
   🖋️ **Create OCR Scan**
    - **Request:**
      ```json
      {
        "recognizedText": "Example text",
        "text": "Any additional notes"
      }
      ```
    - **Response (201):**
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

4. **POST** `/api/user/object-scans`  
   🖼️ **Create Object Scan**
    - **Request:**
      ```json
      {
        "recognizedObjects": "Cat, Dog",
        "text": "Additional context"
      }
      ```
    - **Response (201):**
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

5. **GET** `/api/user/scans`  
   📚 **List All Scans**
    - **Response (200):**
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

6. **GET** `/api/user/scans/:scanId`  
   🔍 **Get Single Scan**
    - **Path Param:** `scanId`
    - **Response (200):**
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

7. **PUT** `/api/user/scans/:scanId`  
   ✏️ **Update Scan**
    - **Request:**
      ```json
      {
        "type": "Text",
        "name": "Updated recognized text",
        "text": "Updated notes"
      }
      ```
    - **Response (200):**
      ```json
      { "message": "OCR scan updated successfully." }
      ```

8. **DELETE** `/api/user/scans/:scanId`  
   🗑️ **Delete Scan**
    - **Response (200):**
      ```json
      { "message": "OCR scan deleted successfully." }
      ```

### 🤖 LLM Features

9. **POST** `/api/user/photo-upload`  
   📸 **Upload Photo for LLM**
    - **Content-Type:** `multipart/form-data`
    - **Form Data:**
        - `media`: Image file (jpg, png, etc.)
        - `description`: String description
    - **Response (201):**
      ```json
      {
        "message": "LLM scan created.",
        "llm_id": 123,
        "file": "user@example.com/2025-06-10/filename.jpg"
      }
      ```

10. **POST** `/api/user/llm-ask-question`  
    💬 **Ask LLM Question**
    - **Request:**
      ```json
      {
        "conversationId": "uuid-string", // optional
        "content": "What's in this image?",
        "base64": "image-data", // optional
        "isStream": false // optional
      }
      ```
    - **Streaming Response:**
      ```json
      {"conversationId": "uuid", "answer": "partial", "done": false}
      {"conversationId": "uuid", "answer": "response", "done": true}
      ```
    - **Non-streaming Response (200):**
      ```json
      {
        "ok": true,
        "status": 200,
        "data": {
          "conversationId": "uuid",
          "answer": "Full response text"
        }
      }
      ```

### 👨‍👦 Guardian Features

11. **POST** `/api/user/guardian/bind-request`  
    📩 **Request Guardian Binding**
    - **Request:**
      ```json
      { "email": "user@example.com" }
      ```
    - **Response (200):**
      ```json
      { "message": "OTP sent." }
      ```

12. **POST** `/api/user/guardian/bind-confirm`  
    ✅ **Confirm Guardian Binding**
    - **Request:**
      ```json
      {
        "email": "user@example.com",
        "codeValue": "123456"
      }
      ```
    - **Response (200):**
      ```json
      { "message": "Guardian bound." }
      ```

13. **GET** `/api/user/guardian/bound-users`  
    👥 **List Bound Users**
    - **Response (200):**
      ```json
      [
        {
          "user_id": 15,
          "email": "user@example.com"
        }
      ]
      ```

14. **GET** `/api/user/guardian/scan-stats`  
    📊 **Get Scan Statistics**
    - **Query Params:** `?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD`
    - **Response (200):**
      ```json
      {
        "objectScanCount": 5,
        "ocrScanCount": 3
      }
      ```

15. **GET** `/api/user/guardian/all-scans/user`  
    📂 **Get User's Scans**
    - **Query Param:** `?user_id=123`
    - **Response (200):**
      ```json
      [
        {
          "scanId": 57,
          "name": "Cat, Dog",
          "type": "Object",
          "createdAt": "2025-06-05T10:00:00.000Z"
        },
        {
          "id": 123,
          "conversation_id": "uuid",
          "first_user_message": "What's this?",
          "type": "LLM",
          "createdAt": "2025-06-05T11:00:00.000Z"
        }
      ]
            ```
      16. **POST** `/api/user/guardian/llm-ask-question`
          🤖 **Ask LLM Question (Guardian)**
          - **Purpose:** A guardian asks a question on behalf of a bound user.
          - **Request:**
            ```json
            {
              "user_id": 123,
              "conversationId": "uuid-string",
              "content": "What is this?",
              "base64": "image-data"
            }
            ```
          - **Response (200):**
            ```json
            {
              "ok": true,
              "status": 200,
              "data": {
                "conversationId": "uuid-string",
                "answer": "Full response text"
              }
            }
            ```
      17. **GET** `/api/user/guardian/:conversationId/image`
          🖼️ **Get Conversation Image**
          - **Purpose:** Fetches the base64 encoded image for a conversation.
          - **Response (200):**
            ```json
            {
              "conversationId": "uuid-string",
              "image": "base64-encoded-string"
            }
            ```
      18. **GET** `/api/user/guardian/conversation/:conversationId/history`
          📜 **Get Conversation History**
          - **Purpose:** Retrieves the message history for a conversation.
          - **Response (200):**
            ```json
            {
              "conversationId": "uuid-string",
              "messages": [
                { "role": "user", "content": "Hello", "createdAt": "..." },
                { "role": "assistant", "content": "Hi there!", "createdAt": "..." }
              ]
            }
            ```
      ### ⭐ Premium Features
      
      19. **GET** `/api/user/premium/status`
          🌟 **Get Premium Status**
          - **Response (200):**
            ```json
            {
              "isPremiumUser": true,
              "premiumExpiration": "2026-06-10T12:00:00.000Z"
            }
            ```
      20. **POST** `/api/user/premium/purchase`
          💳 **Purchase Premium**
          - **Request:**
            ```json
            {
              "amount": 5.00,
              "paymentMethod": "Credit Card"
            }
            ```
          - **Response (200):**
            ```json
            { "message": "Premium purchased successfully." }
            ```
      
      ---
      
      ## ⚙️ Admin Endpoints

### User Management
1.  **GET** `/api/admin/dashboard`
    - **Purpose:** Get dashboard statistics.
2.  **GET** `/api/admin/users`
    - **Purpose:** Get a paginated list of users.
3.  **POST** `/api/admin/users`
    - **Purpose:** Create a new user.
4.  **GET** `/api/admin/users/:userId`
    - **Purpose:** Get a single user by ID.
5.  **PUT** `/api/admin/users/:userId`
    - **Purpose:** Update a user's details.
6.  **DELETE** `/api/admin/users/:userId`
    - **Purpose:** Delete a user.
7.  **GET** `/api/admin/users/:userId/transactions`
    - **Purpose:** Get a user's transaction history.
8.  **PUT** `/api/admin/users/:userId/make-premium`
    - **Purpose:** Upgrade a user to premium.
9.  **PUT** `/api/admin/users/:userId/remove-premium`
    - **Purpose:** Revoke a user's premium status.

### Guardian Management
10. **GET** `/api/admin/users/:userId/guardians`
    - **Purpose:** Get a user's guardians.
11. **POST** `/api/admin/users/:userId/guardians`
    - **Purpose:** Bind a guardian to a user.
12. **DELETE** `/api/admin/users/:userId/guardians/:guardianId`
    - **Purpose:** Unbind a guardian from a user.
13. **GET** `/api/admin/guardians`
    - **Purpose:** List all guardian accounts.
14. **GET** `/api/admin/guardians/:guardianId/bound-users`
    - **Purpose:** Get all users bound to a specific guardian.

### Scan & Conversation Management
15. **GET** `/api/admin/users/:userId/scans`
    - **Purpose:** Get all scans for a specific user.
16. **GET** `/api/admin/scans/:conversationId/images`
    - **Purpose:** Get images from a conversation.
17. **GET** `/api/admin/conversations/:conversationId/history`
    - **Purpose:** Get the history of a conversation.
18. **PUT** `/api/admin/scans/:scanId`
    - **Purpose:** Update a scan.
19. **DELETE** `/api/admin/scans/:scanId`
    - **Purpose:** Delete a scan or a conversation.

### Reporting & Auditing
20. **GET** `/api/admin/report`
    - **Purpose:** Generate a daily user report.
21. **GET** `/api/admin/audit-trail`
    - **Purpose:** Get the audit trail for admin actions.
22. **GET** `/api/admin/users/:userId/activity`
    - **Purpose:** Get the activity log for a specific user.

---

### 📝 Notes

- **All user routes** require valid JWT in `Authorization: Bearer <token>` header
- **Guardian routes** require `accountType: "Guardian"`
- **Admin routes** require `accountType: "Admin"`
- **Error Responses:**
    - `401 Unauthorized`: Missing/invalid token
    - `403 Forbidden`: Insufficient permissions
    - `404 Not Found`: Resource doesn't exist
    - `400 Bad Request`: Invalid input data

Happy integrating! 🎉