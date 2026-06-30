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
| POST | `/api/early-access/request` | No | Submit early access request (rate limited) |
| GET | `/api/user/profile` | Bearer | Get profile |
| GET | `/api/user/capabilities` | Bearer | Platform capabilities (portal toggle) |
| GET | `/api/user/storage` | Bearer | My storage quota summary (+ active pending upgrade request) |
| GET | `/api/user/storage/history` | Bearer | My storage ledger history |
| GET | `/api/user/storage/requests` | Bearer | My storage upgrade requests (status history) |
| POST | `/api/user/storage/request` | Bearer | Submit storage upgrade request (emails superadmin) |
| GET | `/api/user/videos` | Bearer | Owner cross-workspace video library |
| PATCH | `/api/user/profile` | Bearer | Update profile |
| POST | `/api/user/upload/profile-image` | Bearer | Upload profile image (multipart) |
| DELETE | `/api/user/profile-image` | Bearer | Remove profile image |
| GET | `/api/user/inbox` | Bearer | List inbox notifications (`type`, `category`, `workspaceId` filters) |
| GET | `/api/user/inbox/unread-count` | Bearer | Unread inbox count + `byCategory` |
| GET | `/api/user/inbox/:notificationId` | Bearer | Get one inbox notification |
| PATCH | `/api/user/inbox/read` | Bearer | Bulk mark inbox items read |
| PATCH | `/api/user/inbox/read-all` | Bearer | Mark all inbox items read |
| PATCH | `/api/user/inbox/:notificationId/read` | Bearer | Mark one inbox item read |
| DELETE | `/api/user/inbox/:notificationId` | Bearer | Dismiss inbox notification |
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
| GET | `/api/workspaces/:workspaceId/projects/:projectId/comments` | Bearer + member | List project comments |
| POST | `/api/workspaces/:workspaceId/projects/:projectId/comments` | Bearer + member | Create comment |
| PATCH | `/api/workspaces/:workspaceId/projects/:projectId/comments/:commentId` | Bearer + member | Update own comment |
| DELETE | `/api/workspaces/:workspaceId/projects/:projectId/comments/:commentId` | Bearer + member | Delete comment |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/comments/mentionable-users` | Bearer + member | Mention autocomplete |
| POST | `/api/workspaces/:workspaceId/projects/:projectId/renders` | Bearer + member | Start Remotion render |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/renders` | Bearer + member | List project renders |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/renders/:renderId` | Bearer + member | Get render status/details |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/renders/:renderId/download` | Bearer + member | Presigned MP4 URL (`filename` + attachment disposition) |
| GET/HEAD | `/api/workspaces/:workspaceId/projects/:projectId/renders/:renderId/stream` | Bearer + member | Pipe final MP4 through API (download) |
| GET | `/api/workspaces/:workspaceId/storage` | Bearer + member | Workspace footprint + owner quota |
| GET | `/api/workspaces/:workspaceId/videos` | Bearer + member | Workspace video library across projects |
| POST | `/api/assets/:workspaceId/upload` | Bearer + workspace access | Upload workspace asset (multipart `file`) |
| GET | `/api/assets/:workspaceId` | Bearer + workspace access | List workspace assets (`take` / `skip`, optional `source=upload\|stock\|all`) |
| PATCH | `/api/assets/:workspaceId/:assetId/rename` | Bearer + workspace access | Rename asset |
| DELETE | `/api/assets/:workspaceId/:assetId` | Bearer + workspace access | Delete asset |
| GET | `/api/stock/search` | Bearer | Search stock (`q`, `type=photo\|video`, `provider=pexels\|unsplash\|pixabay\|all`, `page`, `perPage`) |
| POST | `/api/stock/workspaces/:workspaceId/import` | Bearer + workspace access | Import stock item → workspace Asset (S3 copy) |
| GET | `/api/credits/:id` | Bearer + OWNER/ADMIN | Workspace credit balance |
| GET | `/api/credits/:id/history` | Bearer + OWNER/ADMIN | Workspace credit history |
| GET | `/api/credits/:id/my-history` | Bearer + any member | My credits in workspace |
| GET | `/api/superadmin/users` | Bearer + platform superadmin | List users (credits + storage) |
| PATCH | `/api/superadmin/users/:userId/platform-access` | Bearer + platform superadmin | Grant/revoke platform superadmin flag |
| GET | `/api/superadmin/users/:userId/credits` | Bearer + platform superadmin | User personal balance |
| GET | `/api/superadmin/users/:userId/credits/history` | Bearer + platform superadmin | User credit ledger |
| POST | `/api/superadmin/users/:userId/credits/grant` | Bearer + platform superadmin | Grant personal credits |
| POST | `/api/superadmin/users/:userId/credits/revoke` | Bearer + platform superadmin | Revoke personal credits |
| GET | `/api/superadmin/users/:userId/storage` | Bearer + platform superadmin | User storage summary |
| GET | `/api/superadmin/users/:userId/storage/history` | Bearer + platform superadmin | User storage ledger |
| POST | `/api/superadmin/users/:userId/storage/grant` | Bearer + platform superadmin | Grant storage bytes/tier |
| POST | `/api/superadmin/users/:userId/storage/revoke` | Bearer + platform superadmin | Revoke storage bytes |
| GET | `/api/superadmin/storage/tiers` | Bearer + platform superadmin | Storage tier presets |
| GET | `/api/superadmin/storage/requests` | Bearer + platform superadmin | Storage upgrade request queue |
| POST | `/api/superadmin/storage/requests/:requestId/reject` | Bearer + platform superadmin | Reject storage upgrade request |
| GET | `/api/superadmin/workspaces` | Bearer + platform superadmin | List TEAM workspaces with pools |
| GET | `/api/superadmin/workspaces/:workspaceId/credits` | Bearer + platform superadmin | Workspace pool summary |
| GET | `/api/superadmin/workspaces/:workspaceId/credits/history` | Bearer + platform superadmin | Workspace credit ledger |
| GET | `/api/superadmin/workspaces/:workspaceId/credits/usage-by-member` | Bearer + platform superadmin | Usage by member |
| POST | `/api/superadmin/workspaces/:workspaceId/credits/grant` | Bearer + platform superadmin | Grant workspace pool credits |
| POST | `/api/superadmin/workspaces/:workspaceId/credits/revoke` | Bearer + platform superadmin | Revoke workspace pool credits |
| GET | `/api/superadmin/reports/credits/usage` | Bearer + platform superadmin | Usage report (aggregates + breakdown) |
| GET | `/api/superadmin/reports/credits/platform-actions` | Bearer + platform superadmin | Platform grant/revoke audit |
| GET | `/api/superadmin/heygen/account` | Bearer + platform superadmin | HeyGen API wallet |
| GET | `/api/superadmin/alerts/summary` | Bearer + platform superadmin | Platform alerts summary |
| POST | `/api/superadmin/broadcasts/product-email` | Bearer + platform superadmin | Product email broadcast (`productEmails` opt-in) |
| GET | `/api/heygen/avatars/groups` | Bearer | HeyGen avatar groups (`ownership=private` filtered per user; optional `workspace_id` merges shared) |
| GET | `/api/heygen/avatars/looks` | Bearer | HeyGen avatar looks (`ownership=private` filtered; optional `workspace_id`) |
| POST | `/api/heygen/avatars/upload` | Bearer | Upload avatar training file to S3; returns public `url` (max ~900 MB) |
| POST | `/api/heygen/voices/upload` | Bearer | Upload voice clone audio to S3; returns public `url` (max ~100 MB) |
| POST | `/api/heygen/avatars` | Bearer | Create HeyGen avatar (records group for private lists) |
| POST | `/api/heygen/avatars/:groupId/consent` | Bearer | HeyGen avatar consent (own group only; else **403**) |
| DELETE | `/api/heygen/avatars/:groupId` | Bearer | Delete custom avatar group (+ paired clone voice; optional `voice_id` query) |
| DELETE | `/api/heygen/avatars/looks/:lookId` | Bearer | Delete one avatar look; last look cascades to group delete |
| DELETE | `/api/heygen/voices/:voiceId` | Bearer | Delete cloned custom voice only (`source: clone`; else **400**) |
| GET | `/api/heygen/voices` | Bearer | List HeyGen voices (`type=private` filtered; optional `workspace_id` merges shared) |
| POST | `/api/heygen/voices` | Bearer | Design voice (suggestions only; does not add to My voices) |
| POST | `/api/heygen/voices/select` | Bearer | Persist user’s chosen voiceId to My voices |
| POST | `/api/heygen/voices/clone` | Bearer | Clone voice (records id for private list) |
| GET | `/api/heygen/voices/:voiceId` | Bearer | Voice detail / clone status (another user’s **clone** → **403**) |
| POST | `/api/heygen/voices/preview-speech` | Bearer | Speech preview |
| POST | `/api/workspaces/:workspaceId/heygen/avatars/:groupId/share` | Bearer + member | Share avatar group with workspace |
| DELETE | `/api/workspaces/:workspaceId/heygen/avatars/:groupId/share` | Bearer + member | Unshare avatar from workspace |
| GET | `/api/workspaces/:workspaceId/heygen/shared-avatars` | Bearer + member | List workspace-shared avatars |
| POST | `/api/workspaces/:workspaceId/heygen/voices/:voiceId/share` | Bearer + member | Share private voice with workspace |
| DELETE | `/api/workspaces/:workspaceId/heygen/voices/:voiceId/share` | Bearer + member | Unshare voice from workspace |
| GET | `/api/workspaces/:workspaceId/heygen/shared-voices` | Bearer + member | List workspace-shared voices |
| POST | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos` | Bearer + member | Create HeyGen avatar video (scene, script, lip sync) |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos` | Bearer + member | List HeyGen video records for project |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId` | Bearer + member | Get / poll / sync to S3 |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/download` | Bearer + member | Presigned MP4 URL (`expiresIn` optional) |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/stream` | Bearer + member | Stream MP4 through API (stable path; use fetch+blob or cookies for `<video>`) |
| HEAD | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/stream` | Bearer + member | Video metadata before streaming |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/heygen/videos/:heygenVideoId/s3-location` | Bearer + member | S3 bucket/key metadata (optional; not needed for editor preview) |
| POST | `/api/workspaces/:workspaceId/projects/:projectId/speech` | Bearer + member | Generate scene speech (TTS audio) |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/speech` | Bearer + member | List speech generations for project |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/speech/:speechId` | Bearer + member | Get speech generation |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/speech/:speechId/download` | Bearer + member | Presigned MP3 URL (`expiresIn` optional) |
| GET | `/api/workspaces/:workspaceId/projects/:projectId/speech/:speechId/stream` | Bearer + member | Stream MP3 through API (stable path) |
| HEAD | `/api/workspaces/:workspaceId/projects/:projectId/speech/:speechId/stream` | Bearer + member | Audio metadata before streaming |

---

### Storage byte fields

Routes under `/api/user/storage`, `/api/workspaces/:id/storage`, and `/api/superadmin/users/:id/storage/*` use **binary bytes** in JSON numbers (`1073741824` = 1 GiB). Superadmin grant accepts `tierId` (preset absolute limit) or `additionalBytes` (increment; no fixed max). Details: [STORAGE_API.md](STORAGE_API.md), [SUPERADMIN_API.md](SUPERADMIN_API.md).

---

**[← API index](README.md)** · [Project root README](../../README.md)

