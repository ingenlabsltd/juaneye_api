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
| POST   | `/api/user/photo-upload`              | Upload Photo for LLM           |
| POST   | `/api/user/llm-ask-question`          | Ask LLM Question               |
| POST   | `/api/user/guardian/bind-request`     | Request Guardian Binding       |
| POST   | `/api/user/guardian/bind-confirm`     | Confirm Guardian Binding       |
| GET    | `/api/user/guardian/bound-users`      | List Bound Users               |
| GET    | `/api/user/guardian/scan-stats`       | Get Scan Statistics            |
| GET    | `/api/user/guardian/all-scans/user`   | Get User's Scans (Guardian)    |
| GET    | `/api/dashboard`                      | Generic Dashboard              |
| GET    | `/api/admin/dashboard`                | Admin Dashboard                |
| GET    | `/api/admin/users?page=<n>&limit=<m>` | List Users (Paginated)         |
| POST   | `/api/admin/users`                    | Create User                    |
| GET    | `/api/admin/users/:userId`            | Get Single User                |
| PUT    | `/api/admin/users/:userId`            | Update User                    |
| DELETE | `/api/admin/users/:userId`            | Delete User                    |
| GET    | `/api/admin/users/:userId/scans`      | List User's Scans              |
| PUT    | `/api/admin/scans/:scanId`            | Update Scan (Admin)            |
| DELETE | `/api/admin/scans/:scanId`            | Delete Scan (Admin)            |
| GET    | `/api/admin/report?date=YYYY-MM-DD`   | Daily User Report              |

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

---

## ⚙️ Admin Endpoints

_(Documentation remains the same as in your original docs)_

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