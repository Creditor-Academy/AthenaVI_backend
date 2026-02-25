# AthenaVI_backend
# 🔐 Authentication API Documentation

This document contains the complete documentation for the Authentication module.

---

## 📌 Base URL

```
/api/auth
```

---

# 📧 OTP APIs

## 1️⃣ Generate OTP

Generate and send an OTP to the user's email.

### Endpoint
```
POST /otp/generate
```

### Request Body
```json
{
  "email": "abhisheksaxena9525@gmail.com"
}
```

### Description
- Generates a new OTP
- Sends OTP to the provided email
- OTP expires after a limited time

---

## 2️⃣ Resend OTP

Resend OTP to the user's email.

### Endpoint
```
POST /otp/resend
```

### Request Body
```json
{
  "email": "abhisheksaxena9525@gmail.com"
}
```

### Description
- Generates a new OTP
- Invalidates previous OTP (if implemented)

---

# 👤 Registration

## 3️⃣ Verify OTP & Register

Verify OTP and create a new user account.

### Endpoint
```
POST /register
```

### Request Body
```json
{
  "name": "Abhishek",
  "email": "abhisheksaxena9525@gmail.com",
  "password": "pass@123",
  "otp": 308856
}
```

### Description
- Verifies OTP
- Hashes password
- Creates user in database
- Returns access token
- Stores refresh token in HTTP-only cookie

---

# 🔑 Login

## 4️⃣ Login User

Authenticate user and generate tokens.

### Endpoint
```
POST /login
```

### Request Body
```json
{
  "email": "abhisheksaxena9525@gmail.com",
  "password": "pass@1234"
}
```

### Description
- Validates credentials
- Returns:
  - Access token (in response body)
  - Refresh token (stored in HTTP-only cookie)

---

# 🔄 Token Management

## 5️⃣ Refresh Access Token

Generate a new access token using refresh token.

### Endpoint
```
POST /refresh
```

### Authentication
- Refresh token must be stored in an HTTP-only cookie

### Description
- Validates refresh token
- Issues new access token
- May rotate refresh token (recommended)

---

# 🚪 Logout

## 6️⃣ Logout (Single Device)

Logout from the current session.

### Endpoint
```
POST /logout
```

### Authentication
- Uses refresh token from HTTP-only cookie

### Description
- Deletes current refresh token
- Clears cookie

---

## 7️⃣ Logout From All Devices

Logout user from all logged-in devices.

### Endpoint
```
POST /logout-all
```

### Authentication
```
Authorization: Bearer <access_token>
```

### Middleware
- Requires `authMiddleware`

### Description
- Deletes all refresh tokens for the user
- Logs user out from all devices

---

# 🔐 Password Reset

## 8️⃣ Forget Password

Send password reset link to email.

### Endpoint
```
POST /forget-password
```

### Request Body
```json
{
  "email": "abhisheksaxena9525@gmail.com"
}
```

### Description
- Generates password reset token
- Sends reset link via email
- Token has expiration time

---

## 9️⃣ Reset Password

Reset password using reset token.

### Endpoint
```
POST /reset-password
```

### Request Body
```json
{
  "token": "b748dae6a20266053b2c33547d0b313eeaadf6362521d66c85170e64e8e88227",
  "newPassword": "pass@1234"
}
```

### Description
- Verifies reset token
- Updates password
- Deletes previous reset tokens

---

# 🔐 Authentication Strategy

## Access Token
- Returned in response body
- Used for protected routes
- Sent as:
  ```
  Authorization: Bearer <access_token>
  ```
- Short-lived

## Refresh Token
- Stored in HTTP-only cookie
- Long-lived
- Stored in database
- Used to generate new access tokens

---

# 🛡 Security Features

- Password hashing (bcrypt)
- HTTP-only cookies
- Refresh token storage in database
- OTP expiration
- Reset token expiration
- Logout from all devices
- Token rotation (recommended)

---

# 🔄 Complete Auth Flow

1. User generates OTP  
2. User verifies OTP and registers  
3. User logs in  
4. Access token used for protected routes  
5. Refresh token generates new access tokens  
6. Logout clears current session  
7. Logout-all clears all sessions  
8. Forget password → Email link → Reset password  

---

**End of Documentation**