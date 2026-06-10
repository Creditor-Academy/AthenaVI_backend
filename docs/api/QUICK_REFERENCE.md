# Quick reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/otp/generate` | No | Send OTP |
| POST | `/api/auth/otp/resend` | No | Resend OTP |
| POST | `/api/auth/register` | No | Register (OTP + password) |
| POST | `/api/auth/login` | No | Login |
| POST | `/api/auth/superadmin/login` | No | Superadmin portal login |
| POST | `/api/auth/refresh` | Cookie | New access token |
| POST | `/api/auth/logout` | Cookie | Logout current device |
| POST | `/api/auth/logout-all` | Bearer | Logout all devices |
| POST | `/api/auth/forget-password` | No | Request reset link |
| POST | `/api/auth/reset-password` | No | Reset password with token |
| GET | `/api/auth/google` | No | Start Google OAuth |
| GET | `/api/auth/superadmin/google` | No | Start Google OAuth (superadmin portal) |
| GET | `/api/auth/google/callback` | No | Google redirect (OAuth) |
| GET | `/api/user/getall` | Bearer | List all users |
| GET | `/api/user/profile` | Bearer | Get profile |
| GET | `/api/user/capabilities` | Bearer | Platform capabilities (portal toggle) |
| PATCH | `/api/user/profile` | Bearer | Update profile |
| POST | `/api/user/upload/profile-image` | Bearer | Upload profile image (multipart) |
| DELETE | `/api/user/profile-image` | Bearer | Remove profile image |
| GET | `/api/user/inbox` | Bearer | List inbox notifications |
| GET | `/api/user/inbox/unread-count` | Bearer | Unread inbox count |
| PATCH | `/api/user/inbox/read-all` | Bearer | Mark all inbox items read |
| PATCH | `/api/user/inbox/:notificationId/read` | Bearer | Mark one inbox item read |
| POST | `/api/workspaces` | Bearer | Create team workspace |
| GET | `/api/workspaces` | Bearer | List my workspaces |
| POST | `/api/workspaces/invitations/accept` | Bearer | Accept invite |
| GET | `/api/workspaces/:id` | Bearer + member | Get workspace |
| PATCH | `/api/workspaces/:id` | Bearer + OWNER | Rename workspace |
| DELETE | `/api/workspaces/:id` | Bearer + OWNER | Delete workspace |
| GET | `/api/workspaces/:id/members` | Bearer + OWNER/ADMIN | List members |
| GET | `/api/workspaces/:id/invitations` | Bearer + OWNER/ADMIN | List pending invitations |
| POST | `/api/workspaces/:id/invite` | Bearer + OWNER/ADMIN | Invite by email |
| DELETE | `/api/workspaces/:id/invitations/:invitationId` | Bearer + OWNER/ADMIN | Cancel invitation |
| PATCH | `/api/workspaces/:id/members/:memberId/role` | Bearer + OWNER | Change role |
| DELETE | `/api/workspaces/:id/members/:memberId` | Bearer + OWNER/ADMIN or self | Remove member |
| GET | `/api/workspaces/:workspaceId/folders` | Bearer | List folders |
| POST | `/api/workspaces/:workspaceId/folders` | Bearer | Create folder |
| PATCH | `/api/workspaces/:workspaceId/folders/:folderId` | Bearer + creator or OWNER/ADMIN | Rename folder |
| DELETE | `/api/workspaces/:workspaceId/folders/:folderId` | Bearer + creator or OWNER/ADMIN | Delete folder |
| POST | `/api/workspaces/:workspaceId/projects` | Bearer + member | Create project |
| GET | `/api/workspaces/:workspaceId/projects` | Bearer + member | List projects (`folderId` optional) |
| GET | `/api/workspaces/:workspaceId/projects/:projectId` | Bearer + member | Get project |
| PATCH | `/api/workspaces/:workspaceId/projects/:projectId` | Bearer + member | Update project metadata |
| PATCH | `/api/workspaces/:workspaceId/projects/:projectId/data` | Bearer + member | Save validated editor state |
| PATCH | `/api/workspaces/:workspaceId/projects/:projectId/move-folder` | Bearer + member | Move project and migrate folder-aware S3 assets |
| DELETE | `/api/workspaces/:workspaceId/projects/:projectId` | Bearer + member | Delete project and related assets |
| POST | `/api/workspaces/:workspaceId/projects/:projectId/renders` | Bearer + member | Start Remotion render |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/renders` | Bearer + member | List project renders |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/renders/:renderId` | Bearer + member | Get render status/details |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/renders/:renderId/download` | Bearer + member | Get final render presigned URL |
| POST | `/api/assets/:workspaceId/upload` | Bearer + workspace access | Upload workspace asset (multipart `file`) |
| GET | `/api/assets/:workspaceId` | Bearer + workspace access | List workspace assets (`take` / `skip`) |
| PATCH | `/api/assets/:workspaceId/:assetId/rename` | Bearer + workspace access | Rename asset |
| DELETE | `/api/assets/:workspaceId/:assetId` | Bearer + workspace access | Delete asset |
| GET | `/api/credits/:id` | Bearer + OWNER/ADMIN | Workspace credit balance |
| GET | `/api/credits/:id/history` | Bearer + OWNER/ADMIN | Workspace credit history |
| GET | `/api/credits/:id/my-history` | Bearer + any member | My credits in workspace |
| GET | `/api/heygen/avatars/groups` | Bearer | HeyGen avatar groups (`ownership=private` filtered per user) |
| GET | `/api/heygen/avatars/looks` | Bearer | HeyGen avatar looks (`ownership=private` filtered per user) |
| POST | `/api/heygen/avatars` | Bearer | Create HeyGen avatar (records group for private lists) |
| POST | `/api/heygen/avatars/:groupId/consent` | Bearer | HeyGen avatar consent (own group only; else **403**) |
| GET | `/api/heygen/voices` | Bearer | List HeyGen voices (`type=private` filtered per user) |
| POST | `/api/heygen/voices` | Bearer | Design voice (suggestions only; does not add to My voices) |
| POST | `/api/heygen/voices/select` | Bearer | Persist user’s chosen voiceId to My voices |
| POST | `/api/heygen/voices/clone` | Bearer | Clone voice (records id for private list) |
| GET | `/api/heygen/voices/:voiceId` | Bearer | Voice detail / clone status (another user’s **clone** → **403**) |
| POST | `/api/heygen/voices/preview-speech` | Bearer | Speech preview |
| POST | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos` | Bearer + member | Create HeyGen avatar video (scene, script, lip sync) |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos` | Bearer + member | List HeyGen video records for project |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId` | Bearer + member | Get / poll / sync to S3 |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/download` | Bearer + member | Presigned MP4 URL (`expiresIn` optional) |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/stream` | Bearer + member | Stream MP4 through API (stable path; use fetch+blob or cookies for `<video>`) |
| HEAD | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/stream` | Bearer + member | Video metadata before streaming |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/s3-location` | Bearer + member | S3 bucket/key metadata (optional; not needed for editor preview) |

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

