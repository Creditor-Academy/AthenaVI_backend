# AthenaVI Backend - API Documentation

## Overview
This document provides comprehensive documentation for all API endpoints in the AthenaVI Backend system, including routes, parameters, authentication requirements, request bodies, and response formats.

---

## Table of Contents
1. [Authentication Module](#authentication-module)
2. [User Module](#user-module)
3. [Workspace Module](#workspace-module)
4. [Folder Module](#folder-module)
5. [Asset Module](#asset-module)
6. [Credit Module](#credit-module)
7. [HeyGen Module](#heygen-module)

---

## Authentication Module

### Base URL: `/api/auth`

#### 1. Generate OTP
- **Method:** `POST`
- **Route:** `/otp/generate`
- **Token Required:** No
- **Body Parameters:**
  ```json
  {
    "email": "user@example.com"  // string, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:** None
- **Response (200):**
  ```json
  {
    "success": true,
    "data": null,
    "message": "OTP sent successfully"
  }
  ```

#### 2. Resend OTP
- **Method:** `POST`
- **Route:** `/otp/resend`
- **Token Required:** No
- **Body Parameters:**
  ```json
  {
    "email": "user@example.com"  // string, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:** None
- **Response (200):**
  ```json
  {
    "success": true,
    "data": null,
    "message": "OTP sent successfully"
  }
  ```

#### 3. Register User
- **Method:** `POST`
- **Route:** `/register`
- **Token Required:** No
- **Body Parameters:**
  ```json
  {
    "name": "John Doe",         // string, min 2, max 50, required
    "email": "user@example.com",// string, valid email, required
    "password": "password123",  // string, min 6, required
    "otp": 123456              // number, 6 digits, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:** None
- **Response (201):**
  ```json
  {
    "success": true,
    "data": {
      "accessToken": "jwt_token_here",
      "user": {
        "id": "user-uuid",
        "email": "user@example.com",
        "name": "John Doe"
      }
    },
    "message": "User created successfully"
  }
  ```

#### 4. Login
- **Method:** `POST`
- **Route:** `/login`
- **Token Required:** No
- **Body Parameters:**
  ```json
  {
    "email": "user@example.com",// string, valid email, required
    "password": "password123"   // string, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:** None
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "accessToken": "jwt_token_here",
      "user": {
        "id": "user-uuid",
        "email": "user@example.com",
        "name": "John Doe"
      }
    },
    "message": "Login successful"
  }
  ```

#### 5. Refresh Token
- **Method:** `POST`
- **Route:** `/refresh`
- **Token Required:** No (uses refresh token from cookie)
- **Body Parameters:** None
- **Query Parameters:** None
- **Path Parameters:** None
- **Headers:** 
  - `Cookie: refreshToken=...` (httpOnly cookie)
- **Response (201):**
  ```json
  {
    "success": true,
    "data": {
      "accessToken": "new_jwt_token_here"
    },
    "message": "Token generated successfully"
  }
  ```

#### 6. Logout
- **Method:** `POST`
- **Route:** `/logout`
- **Token Required:** No
- **Body Parameters:** None
- **Query Parameters:** None
- **Path Parameters:** None
- **Headers:**
  - `Cookie: refreshToken=...` (httpOnly cookie)
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {},
    "message": "Logged out successfully"
  }
  ```

#### 7. Logout All Devices
- **Method:** `POST`
- **Route:** `/logout-all`
- **Token Required:** Yes (Bearer Token)
- **Body Parameters:** None
- **Query Parameters:** None
- **Path Parameters:** None
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {},
    "message": "Logged out successfully"
  }
  ```

#### 8. Forget Password
- **Method:** `POST`
- **Route:** `/forget-password`
- **Token Required:** No
- **Body Parameters:**
  ```json
  {
    "email": "user@example.com"  // string, valid email, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:** None
- **Response (200):**
  ```json
  {
    "success": true,
    "data": null,
    "message": "Password reset link sent"
  }
  ```

#### 9. Reset Password
- **Method:** `POST`
- **Route:** `/reset-password`
- **Token Required:** No
- **Body Parameters:**
  ```json
  {
    "token": "reset_token_here",   // string, required
    "newPassword": "newPassword123" // string, min 6, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:** None
- **Response (200):**
  ```json
  {
    "success": true,
    "data": null,
    "message": "Password reset successful"
  }
  ```

#### 10. Google OAuth Redirect
- **Method:** `GET`
- **Route:** `/google`
- **Token Required:** No
- **Query Parameters:** None
- **Path Parameters:** None
- **Response:** Redirects to Google OAuth consent screen

#### 11. Google OAuth Callback
- **Method:** `GET`
- **Route:** `/google/callback`
- **Token Required:** No
- **Query Parameters:**
  ```
  ?code=google_auth_code&state=state_value
  ```
- **Path Parameters:** None
- **Response:** Redirects to frontend with access token in URL hash
  ```
  https://frontend.com/auth/callback#access_token=jwt_token_here
  ```

---

## User Module

### Base URL: `/api/user`

#### 1. Get All Users
- **Method:** `GET`
- **Route:** `/getall`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:** None
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "users": [
        {
          "id": "user-uuid",
          "email": "user@example.com",
          "name": "John Doe",
          "profileImage": null
        }
      ],
      "count": 1
    },
    "message": "Users fetched successfully"
  }
  ```

#### 2. Get User Profile
- **Method:** `GET`
- **Route:** `/profile`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:** None
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "profile": {
        "id": "user-uuid",
        "email": "user@example.com",
        "name": "John Doe",
        "phoneNumber": "+1(310)1234567",
        "profileImage": "image_url"
      }
    },
    "message": "User profile fetched successfully"
  }
  ```

#### 3. Update User Profile
- **Method:** `PATCH`
- **Route:** `/profile`
- **Token Required:** Yes (Bearer Token)
- **Body Parameters:**
  ```json
  {
    "name": "Jane Doe",                        // string, min 2, max 100, optional
    "phoneNumber": "+1(310)1234567"           // string, optional
  }
  ```
- **Query Parameters:** None
- **Path Parameters:** None
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "profile": {
        "id": "user-uuid",
        "email": "user@example.com",
        "name": "Jane Doe",
        "phoneNumber": "+1(310)1234567",
        "profileImage": "image_url"
      }
    },
    "message": "User profile fetched successfully"
  }
  ```

#### 4. Upload Profile Image
- **Method:** `POST`
- **Route:** `/upload/profile-image`
- **Token Required:** Yes (Bearer Token)
- **Body Parameters:** 
  - Multipart form data with file field: `profileImage`
  - File Types: image files
- **Query Parameters:** None
- **Path Parameters:** None
- **Headers:**
  - `Authorization: Bearer <access_token>`
  - `Content-Type: multipart/form-data`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "profile": {
        "id": "user-uuid",
        "email": "user@example.com",
        "name": "John Doe",
        "profileImage": "s3_image_url"
      }
    },
    "message": "Profile image uploaded successfully"
  }
  ```

#### 5. Delete Profile Image
- **Method:** `DELETE`
- **Route:** `/profile-image`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:** None
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "profile": {
        "id": "user-uuid",
        "email": "user@example.com",
        "name": "John Doe",
        "profileImage": null
      }
    },
    "message": "Profile image deleted successfully"
  }
  ```

---

## Workspace Module

### Base URL: `/api/workspaces`

#### 1. Create Workspace
- **Method:** `POST`
- **Route:** `/`
- **Token Required:** Yes (Bearer Token)
- **Body Parameters:**
  ```json
  {
    "name": "My Workspace"  // string, min 3, max 100, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:** None
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (201):**
  ```json
  {
    "success": true,
    "data": {
      "workspace": {
        "id": "workspace-uuid",
        "name": "My Workspace",
        "ownerId": "user-uuid",
        "createdAt": "2026-04-10T12:00:00Z"
      }
    },
    "message": "Workspace created successfully"
  }
  ```

#### 2. Get User Workspaces
- **Method:** `GET`
- **Route:** `/`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:** None
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "workspaces": [
        {
          "id": "workspace-uuid",
          "name": "My Workspace",
          "ownerId": "user-uuid",
          "createdAt": "2026-04-10T12:00:00Z"
        }
      ],
      "count": 1
    },
    "message": null
  }
  ```

#### 3. Get Workspace by ID
- **Method:** `GET`
- **Route:** `/:workspaceId`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  ```
- **Role Required:** OWNER, ADMIN, or MEMBER
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "workspace": {
        "id": "workspace-uuid",
        "name": "My Workspace",
        "ownerId": "user-uuid",
        "createdAt": "2026-04-10T12:00:00Z"
      }
    },
    "message": null
  }
  ```

#### 4. Delete Workspace
- **Method:** `DELETE`
- **Route:** `/:workspaceId`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  ```
- **Role Required:** OWNER only
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": null,
    "message": "Workspace deleted successfully"
  }
  ```

#### 5. Get Workspace Members
- **Method:** `GET`
- **Route:** `/:workspaceId/members`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  ```
- **Role Required:** OWNER or ADMIN
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "members": [
        {
          "id": "member-uuid",
          "userId": "user-uuid",
          "workspaceId": "workspace-uuid",
          "role": "OWNER",
          "user": {
            "name": "John Doe",
            "email": "user@example.com"
          }
        }
      ]
    },
    "message": null
  }
  ```

#### 6. Invite Member
- **Method:** `POST`
- **Route:** `/:workspaceId/invite`
- **Token Required:** Yes (Bearer Token)
- **Body Parameters:**
  ```json
  {
    "email": "newmember@example.com", // string, valid email, required
    "role": "MEMBER"                  // string, enum: OWNER|ADMIN|MEMBER, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  ```
- **Role Required:** OWNER or ADMIN
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (201):**
  ```json
  {
    "success": true,
    "data": {},
    "message": "Invitation sent successfully"
  }
  ```

#### 7. Get Workspace Invitations
- **Method:** `GET`
- **Route:** `/:workspaceId/invitations`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  ```
- **Role Required:** OWNER or ADMIN
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "invitations": [
        {
          "id": "invitation-uuid",
          "email": "newmember@example.com",
          "role": "MEMBER",
          "token": "invitation_token",
          "status": "PENDING"
        }
      ]
    },
    "message": "Workspace invitations fetched successfully"
  }
  ```

#### 8. Cancel Invitation
- **Method:** `DELETE`
- **Route:** `/:workspaceId/invitations/:invitationId`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  invitationId: uuid (required)
  ```
- **Role Required:** OWNER or ADMIN
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {},
    "message": "Invitation cancelled successfully"
  }
  ```

#### 9. Accept Invitation
- **Method:** `POST`
- **Route:** `/invitations/accept`
- **Token Required:** Yes (Bearer Token)
- **Body Parameters:**
  ```json
  {
    "token": "invitation_token"  // string, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:** None
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "workspace": {
        "id": "workspace-uuid",
        "name": "My Workspace",
        "ownerId": "user-uuid"
      }
    },
    "message": "Invitation accepted successfully"
  }
  ```

#### 10. Remove Member
- **Method:** `DELETE`
- **Route:** `/:workspaceId/members/:memberId`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  memberId: uuid (required)
  ```
- **Role Required:** OWNER or ADMIN
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": null,
    "message": "Member removed successfully"
  }
  ```

#### 11. Change Member Role
- **Method:** `PATCH`
- **Route:** `/:workspaceId/members/:memberId/role`
- **Token Required:** Yes (Bearer Token)
- **Body Parameters:**
  ```json
  {
    "role": "ADMIN"  // string, enum: OWNER|ADMIN|MEMBER, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  memberId: uuid (required)
  ```
- **Role Required:** OWNER only
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "member": {
        "id": "member-uuid",
        "userId": "user-uuid",
        "workspaceId": "workspace-uuid",
        "role": "ADMIN"
      }
    },
    "message": "Role updated successfully"
  }
  ```

---

## Folder Module

### Base URL: `/api/workspaces/:workspaceId/folders`

#### 1. Create Folder
- **Method:** `POST`
- **Route:** `/`
- **Token Required:** Yes (Bearer Token)
- **Body Parameters:**
  ```json
  {
    "name": "My Folder"  // string, min 1, max 255, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  ```
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (201):**
  ```json
  {
    "success": true,
    "data": {
      "folder": {
        "id": "folder-uuid",
        "name": "My Folder",
        "workspaceId": "workspace-uuid",
        "createdAt": "2026-04-10T12:00:00Z"
      }
    },
    "message": "Folder created successfully"
  }
  ```

#### 2. Get Folders
- **Method:** `GET`
- **Route:** `/`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  ```
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "folders": [
        {
          "id": "folder-uuid",
          "name": "My Folder",
          "workspaceId": "workspace-uuid",
          "createdAt": "2026-04-10T12:00:00Z"
        }
      ]
    },
    "message": "Folders fetched successfully"
  }
  ```

#### 3. Rename Folder
- **Method:** `PATCH`
- **Route:** `/:folderId`
- **Token Required:** Yes (Bearer Token)
- **Body Parameters:**
  ```json
  {
    "name": "Updated Folder Name"  // string, min 1, max 255, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  folderId: uuid (required)
  ```
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "folder": {
        "id": "folder-uuid",
        "name": "Updated Folder Name",
        "workspaceId": "workspace-uuid"
      }
    },
    "message": "Folder renamed successfully"
  }
  ```

#### 4. Delete Folder
- **Method:** `DELETE`
- **Route:** `/:folderId`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  folderId: uuid (required)
  ```
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "folder": {
        "id": "folder-uuid",
        "name": "My Folder",
        "workspaceId": "workspace-uuid"
      }
    },
    "message": "Folder deleted successfully"
  }
  ```

---

## Asset Module

### Base URL: `/api/assets`

#### 1. Upload Asset
- **Method:** `POST`
- **Route:** `/:workspaceId/upload`
- **Token Required:** Yes (Bearer Token)
- **Body Parameters:** 
  - Multipart form data with file field: `file`
  - File Types: supported asset files
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  ```
- **Headers:**
  - `Authorization: Bearer <access_token>`
  - `Content-Type: multipart/form-data`
- **Response (201):**
  ```json
  {
    "success": true,
    "data": {
      "asset": {
        "id": "asset-uuid",
        "name": "file.mp4",
        "url": "s3_url",
        "workspaceId": "workspace-uuid",
        "createdAt": "2026-04-10T12:00:00Z"
      }
    },
    "message": "Asset uploaded successfully"
  }
  ```

#### 2. Get Assets
- **Method:** `GET`
- **Route:** `/:workspaceId`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:**
  ```
  take: number (optional, min 1, max 100) - limit
  skip: number (optional, min 0) - offset
  ```
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  ```
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "assets": [
        {
          "id": "asset-uuid",
          "name": "file.mp4",
          "url": "s3_url",
          "workspaceId": "workspace-uuid",
          "createdAt": "2026-04-10T12:00:00Z"
        }
      ]
    },
    "message": "Assets fetched successfully"
  }
  ```

#### 3. Rename Asset
- **Method:** `PATCH`
- **Route:** `/:workspaceId/:assetId/rename`
- **Token Required:** Yes (Bearer Token)
- **Body Parameters:**
  ```json
  {
    "name": "new_filename.mp4"  // string, min 1, max 255, required
  }
  ```
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  assetId: uuid (required)
  ```
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "asset": {
        "id": "asset-uuid",
        "name": "new_filename.mp4",
        "url": "s3_url",
        "workspaceId": "workspace-uuid"
      }
    },
    "message": "Asset renamed successfully"
  }
  ```

#### 4. Delete Asset
- **Method:** `DELETE`
- **Route:** `/:workspaceId/:assetId`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:**
  ```
  workspaceId: uuid (required)
  assetId: uuid (required)
  ```
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "asset": {
        "id": "asset-uuid",
        "name": "file.mp4",
        "workspaceId": "workspace-uuid"
      }
    },
    "message": "Asset deleted successfully"
  }
  ```

---

## Credit Module

### Base URL: `/api/credits`

#### 1. Get Credits
- **Method:** `GET`
- **Route:** `/:id`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:** None
- **Path Parameters:**
  ```
  id: uuid (workspaceId, required)
  ```
- **Role Required:** OWNER or ADMIN
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "workspaceId": "workspace-uuid",
      "credits": 1000
    },
    "message": "Credits fetched successfully"
  }
  ```

#### 2. Get Workspace Credit History
- **Method:** `GET`
- **Route:** `/:id/history`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:**
  ```
  page: number (optional, default 1) - page number
  limit: number (optional, default 20) - items per page
  ```
- **Path Parameters:**
  ```
  id: uuid (workspaceId, required)
  ```
- **Role Required:** OWNER or ADMIN
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "history": [
        {
          "id": "history-uuid",
          "workspaceId": "workspace-uuid",
          "userId": "user-uuid",
          "type": "SPENT|EARNED",
          "amount": 50,
          "description": "Video generation",
          "createdAt": "2026-04-10T12:00:00Z"
        }
      ]
    },
    "message": "Credit history fetched successfully"
  }
  ```

#### 3. Get User Credit History
- **Method:** `GET`
- **Route:** `/:id/my-history`
- **Token Required:** Yes (Bearer Token)
- **Query Parameters:**
  ```
  page: number (optional, default 1) - page number
  limit: number (optional, default 20) - items per page
  ```
- **Path Parameters:**
  ```
  id: uuid (workspaceId, required)
  ```
- **Role Required:** OWNER, ADMIN, or MEMBER
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "success": true,
    "data": {
      "history": [
        {
          "id": "history-uuid",
          "workspaceId": "workspace-uuid",
          "userId": "user-uuid",
          "type": "SPENT|EARNED",
          "amount": 50,
          "description": "Video generation",
          "createdAt": "2026-04-10T12:00:00Z"
        }
      ]
    },
    "message": "Credit history fetched successfully"
  }
  ```

---

## HeyGen Module

### Base URL: `/api/heygen`

All endpoints below require **`Authorization: Bearer <access_token>`**.

Proxies **HeyGen v3** (avatars, voices). Requires **`HEYGEN_API_KEY`** on the server (otherwise **500**). Optional **`HEYGEN_BASE_URL`** overrides the API host.

Avatar/lip-sync **video** generation lives under **`/api/workspaces/:workspaceId/projects/:projectId/heygen`** — not on `/api/heygen`.

### User-scoped private assets

Because the server shares one HeyGen API key, “private” listings from HeyGen would mix all tenants. This backend **persists ownership per user** (`heygen_avatars`, `heygen_voices`):

| Endpoint | Extra behavior |
|----------|----------------|
| `GET /avatars/groups?ownership=private` | Only groups recorded when **this user** called `POST /avatars`. |
| `GET /avatars/looks?ownership=private` | Only looks for groups owned by **this user**. With **`group_id`** + **`ownership=private`**, group must be owned or **403** (`HEYGEN_FORBIDDEN`). |
| `GET /voices?type=private` | Only voices from **this user’s** `POST /voices` (design) or `POST /voices/clone`. |
| `POST /avatars/:groupId/consent` | **403** if `groupId` is not owned by **this user**. |
| `GET /voices/:voiceId` | **403** if the voice id is stored as **another user’s** private voice; untracked ids still proxy HeyGen (public catalog). |

Public queries (`ownership=public`, `type=public`, etc.) are **not** user-filtered. Assets created before tracking shipped are **not** in private filtered lists until recreated or backfilled.

---

#### List avatar groups
- **Method:** `GET`
- **Route:** `/avatars/groups`
- **Query:** `ownership` (`public` \| `private`), `limit` (1–50), `token` (cursor), optional extras forwarded to HeyGen
- **Response:** **200** — `data`: HeyGen payload

---

#### List avatar looks
- **Method:** `GET`
- **Route:** `/avatars/looks`
- **Query:** `group_id`, `avatar_type` (`studio_avatar` \| `digital_twin` \| `photo_avatar`), `ownership`, `limit`, `token`
- **Response:** **200** — `data`: HeyGen payload
- **403** — private listing with another user’s `group_id`

---

#### Create avatar
- **Method:** `POST`
- **Route:** `/avatars`
- **Body (JSON):** `type`: `digital_twin` \| `photo` \| `prompt` (required); `name` (required, max 200); for `prompt`, non-empty `prompt`; for `digital_twin` / `photo`, `file` object per HeyGen v3; optional `reference_images`, `avatar_group_id`, …
- **Response:** **200** — `data`: HeyGen response; server records avatar group id when returned for private filtering

---

#### Avatar consent
- **Method:** `POST`
- **Route:** `/avatars/:groupId/consent`
- **Body (optional):** `{ "reroute_url": "https://..." }`
- **Response:** **200** — `data`: HeyGen payload
- **403** — `HEYGEN_FORBIDDEN` if not owner of `groupId`

---

#### List voices
- **Method:** `GET`
- **Route:** `/voices`
- **Query:** `type` (`public` \| `private`), `engine`, `language`, `gender`, `limit` (1–100), `token`
- **Response:** **200** — `data`: HeyGen payload

---

#### Design voice (POST /v3/voices)
- **Method:** `POST`
- **Route:** `/voices`
- **Body:** `prompt` (1–1000 chars, required); optional `gender`, `locale`, `seed`
- **Response:** **200** — `data`: HeyGen payload; returned voice ids recorded for current user

---

#### Clone voice
- **Method:** `POST`
- **Route:** `/voices/clone`
- **Body:** `voice_name` (required); `audio` object (required, HeyGen asset union); optional `language`, `remove_background_noise`
- **Response:** **200** — `data`: HeyGen clone payload; clone id recorded for current user

---

#### Get voice by id
- **Method:** `GET`
- **Route:** `/voices/:voiceId`
- **Response:** **200** — `data`: HeyGen voice payload
- **403** — another user’s private tracked voice

---

#### Preview speech
- **Method:** `POST`
- **Route:** `/voices/preview-speech`
- **Body:** `text` (1–5000, required); `voice_id` (required); optional `input_type`, `speed`, `language`, `locale`
- **Response:** **200** — `data`: HeyGen payload

---

## Common Response Format

All API responses follow this standard format:

```json
{
  "success": true|false,
  "data": {} | null,
  "message": "Success message" | null,
  "timestamp": "2026-04-10T12:00:00Z"
}
```

### Status Codes
- `200` - OK
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error

---

## Authentication

### Bearer Token Format
```
Authorization: Bearer <access_token>
```

### Token in Cookie Format
- `refreshToken`: httpOnly cookie set automatically on auth endpoints

### Middleware Requirements
- **authMiddleware**: Validates JWT token from Authorization header
- **requireWorkspaceRole**: Validates user role within workspace (OWNER, ADMIN, MEMBER)
- **checkWorkspaceAccess**: Validates user access to workspace
- **folderPermission**: Validates user permission to access folder

---

## Validation Rules

### Email Validation
- Must be a valid email format
- Example: `user@example.com`

### Password Validation
- Minimum 6 characters
- No other specific requirements specified

### Phone Number Validation
- Can contain digits, +, -, (), and one space
- Minimum 8 characters
- Maximum 20 characters
- Examples: `+1(310)1234567`, `+1(310) 1234567`

### UUID Validation
- Must be valid UUID format
- Example: `550e8400-e29b-41d4-a716-446655440000`

### Name Validation
- Minimum 2 characters
- Maximum 50-100 characters (depends on context)

---

## Error Handling

Error responses will follow this format:

```json
{
  "success": false,
  "data": null,
  "message": "Error description",
  "timestamp": "2026-04-10T12:00:00Z"
}
```

---

## Notes

1. All timestamps are in ISO 8601 format
2. All UUIDs are in standard UUID v4 format
3. Workspace roles: OWNER, ADMIN, MEMBER
4. HeyGen v3 proxy and workspace HeyGen video routes are implemented; see **HeyGen Module** and README **HeyGen API** / **HeyGen avatar videos** for behavior details
5. File uploads use multipart/form-data
6. Images are stored on S3 and URLs are returned in responses
