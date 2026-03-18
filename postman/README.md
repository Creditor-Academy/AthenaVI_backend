# Postman collection – Athena VI Backend API

## Import

1. Open Postman → **Import** → choose `AthenaVI_Backend_API.postman_collection.json`.
2. The collection **Athena VI Backend API** will appear with folders: Auth, User, Workspaces, Videos, Credits.

## Variables

Set in the collection (or environment):

| Variable       | Example              | Description |
|----------------|----------------------|-------------|
| `baseUrl`      | `http://localhost:9000` | API base URL (no trailing slash). |
| `accessToken`  | *(empty initially)*   | Set automatically after **Login**; used as Bearer token for protected routes. |
| `workspaceId`  | *(UUID)*              | Set automatically after **Create Workspace**; used in workspace-scoped requests. |
| `videoId`      | *(UUID)*              | Set automatically after **Create Video**. |
| `sceneId`      | *(UUID)*              | Set automatically after **Create Scene**. |
| `jobId`        | *(UUID)*              | Set automatically after **Start Render**; use with **Get Render Job Status**. |
| `memberId`     | *(UUID)*              | From **Get Workspace Members**; use for **Change Member Role** / **Remove Member**. |
| `invitationId`  | *(UUID)*              | From **Get Workspace Invitations**; use for **Cancel Invitation**. |

## Flow

1. Set **baseUrl** (e.g. `http://localhost:9000`).
2. Run **Auth → Login** (use real email/password). This saves `accessToken` to the collection.
3. Create a workspace: **Workspaces → Create Workspace**. This saves `workspaceId`.
4. Use **Videos** and **Credits** with the same `workspaceId`; create video → create scenes → align timeline → start render → poll render job.

Auth routes (OTP, Register, Login, Refresh, Logout, Forget/Reset Password, Google) use **No Auth**. All other requests use **Bearer Token** and take `accessToken` from the collection variable.
