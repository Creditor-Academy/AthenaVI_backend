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
| GET | `/api/workspaces/invitations/:token` | — | Preview invite (signup vs login) |
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
| GET | `/api/workspaces/:workspaceId/library` | Bearer + member | Content tabs: omit `category` for counts; `category=video\|presentation\|image` lists items |
| POST | `/api/workspaces/:workspaceId/presentations` | Bearer + member | Create presentation (`blank` \| `template` \| `pack`) |
| GET | `/api/workspaces/:workspaceId/presentations` | Bearer + member | List presentations (`folderId` optional) |
| GET | `/api/workspaces/:workspaceId/presentation-templates` | Bearer + member | List DECK_LAYOUT templates + categories (`?category=` / `?contentType=`) |
| GET | `/api/workspaces/:workspaceId/presentation-deck-packs` | Bearer + member | List DECK_PACK multi-slide packs (summary) |
| GET | `/api/workspaces/:workspaceId/presentation-deck-packs/:packId` | Bearer + member | Get one DECK_PACK (full schema + slidePreviews) |
| GET | `/api/workspaces/:workspaceId/brand-kits` | Bearer + member | List workspace Brand Kits |
| POST | `/api/workspaces/:workspaceId/brand-kits` | Bearer + OWNER/ADMIN | Create Brand Kit |
| GET | `/api/workspaces/:workspaceId/brand-kits/:brandKitId` | Bearer + member | Get Brand Kit |
| PATCH | `/api/workspaces/:workspaceId/brand-kits/:brandKitId` | Bearer + OWNER/ADMIN | Update Brand Kit |
| DELETE | `/api/workspaces/:workspaceId/brand-kits/:brandKitId` | Bearer + OWNER/ADMIN | Delete Brand Kit |
| POST | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/set-default` | Bearer + OWNER/ADMIN | Set default Brand Kit |
| GET | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/health` | Bearer + member | Brand Kit completeness score |
| POST | `/api/workspaces/:workspaceId/brand-kits/suggest/colors` | Bearer + OWNER/ADMIN | AI suggest palette from logo |
| POST | `/api/workspaces/:workspaceId/brand-kits/suggest/fonts` | Bearer + OWNER/ADMIN | AI suggest font pairing |
| POST | `/api/workspaces/:workspaceId/brand-kits/suggest/voice` | Bearer + OWNER/ADMIN | AI expand brand voice |
| POST | `/api/workspaces/:workspaceId/brand-kits/suggest/image-style` | Bearer + OWNER/ADMIN | AI suggest image brief + chart colors |
| POST | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/suggest/logo-variants` | Bearer + OWNER/ADMIN | Generate logo variants |
| GET | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/mockups/catalog` | Bearer + member | Logo mockup catalog + free quota |
| GET | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/mockups` | Bearer + member | Saved logo mockups + free quota |
| POST | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/mockups/generate` | Bearer + OWNER/ADMIN | Generate logo product mockup |
| POST | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/guidelines/generate` | Bearer + OWNER/ADMIN | Generate 6-slide guideline deck |
| GET | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/guidelines` | Bearer + member | Guideline presentation link |
| GET | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/guidelines/pdf` | Bearer + member | Download brand guideline PDF |
| POST | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/media` | Bearer + OWNER/ADMIN | Upload logo/photo/graphic |
| DELETE | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/media/:mediaId` | Bearer + OWNER/ADMIN | Delete Brand Kit media |
| GET | `/api/workspaces/:workspaceId/brand-kits/:brandKitId/media/:mediaId/stream` | Bearer + member | Stream Brand Kit media |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/apply-brand-kit` | Bearer + member | Apply Brand Kit to deck |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId/media` | Bearer + member | Upload image onto slide |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId/attach-asset` | Bearer + member | Attach workspace Asset to slide |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId/insert-stock` | Bearer + member | Insert stock photo onto slide |
| GET | `/api/superadmin/templates/:templateId/media` | Superadmin | List template media |
| POST | `/api/superadmin/templates/:templateId/media` | Superadmin | Upload template media |
| DELETE | `/api/superadmin/templates/:templateId/media/:mediaId` | Superadmin | Delete template media |
| GET | `/api/workspaces/:workspaceId/presentation-themes` | Bearer + member | List curated themes |
| GET | `/api/workspaces/:workspaceId/presentation-elements` | Bearer + member | Element library presets |
| GET | `/api/workspaces/:workspaceId/presentations/:presentationId` | Bearer + member | Get presentation + deck + slides |
| GET | `/api/workspaces/:workspaceId/presentations/:presentationId/status` | Bearer + member | Generation progress |
| GET | `/api/workspaces/:workspaceId/presentations/:presentationId/credit-estimate` | Bearer + member | Outline/generate/export AC estimate |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/outline` | Bearer + member | Generate outline (prompt/outline/document) |
| PATCH | `/api/workspaces/:workspaceId/presentations/:presentationId/outline` | Bearer + member | Update outline JSON |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/theme` | Bearer + member | Set theme |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/generate` | Bearer + member | Start deck generation (202) |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/slides` | Bearer + member | Add slide; optional `generate`+`prompt` for add+AI (deck max 40) |
| DELETE | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId` | Bearer + member | Delete slide |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId/duplicate` | Bearer + member | Duplicate slide |
| PATCH | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/reorder` | Bearer + member | Reorder slides |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId/apply-layout` | Bearer + member | Apply DECK_LAYOUT |
| PUT | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId/canvas` | Bearer + member | Save freeform canvas |
| POST/PATCH/DELETE | `.../slides/:slideId/elements...` | Bearer + member | Element CRUD / reorder |
| PATCH | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId` | Bearer + member | Patch slide |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/slides/:slideId/regenerate` | Bearer + member | Regenerate slide (`prompt` optional; 202) |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/export` | Bearer + member | Queue PPTX/PDF/PNG/JPEG export (202) |
| GET | `/api/workspaces/:workspaceId/presentations/:presentationId/export/:exportId` | Bearer + member | Poll export status |
| PUT | `/api/workspaces/:workspaceId/presentations/:presentationId/share` | Bearer + member | Enable view-only share link (`share.url` always returned) |
| GET | `/api/workspaces/:workspaceId/presentations/:presentationId/share` | Bearer + member | Share link + copyable `share.url` |
| PATCH | `/api/workspaces/:workspaceId/presentations/:presentationId/share` | Bearer + member | Enable/disable or set `expiresAt` (includes `share.url`) |
| POST | `/api/workspaces/:workspaceId/presentations/:presentationId/share/rotate` | Bearer + member | Rotate token; invalidates shared URLs |
| GET | `/api/p/:token` | Public (optional Bearer) | Shared deck, view-only (ETag) |
| GET | `/api/p/:token/session` | Public (optional Bearer) | Viewer display name + `canOpenInEditor` |
| PUT | `/api/p/:token/presence` | Public (optional Bearer) | Presence heartbeat → live viewer list |
| GET | `/api/p/:token/presence` | Public (optional Bearer) | Live viewer list |
| DELETE | `/api/p/:token/presence` | Public (optional Bearer) | Leave preview (`viewerSessionId` query) |
| GET | `/api/workspaces/:workspaceId/video-templates` | Bearer + member | List active VIDEO_SCENE / VIDEO_PACK (`?type=`) |
| GET | `/api/workspaces/:workspaceId/video-templates/:templateId` | Bearer + member | Get one video template |
| POST | `/api/workspaces/:workspaceId/projects` | Bearer + member | Create VIDEO project (optional `templateId` scene or pack) |
| POST | `/api/superadmin/presentations/:presentationId/publish-as-pack` | Superadmin | Publish PPT canvas as DECK_PACK |
| POST | `/api/superadmin/projects/:projectId/scenes/:sceneId/publish-as-template` | Superadmin | Publish scene as VIDEO_SCENE |
| POST | `/api/superadmin/projects/:projectId/publish-as-video-pack` | Superadmin | Publish project as VIDEO_PACK |
| GET | `/api/workspaces/:workspaceId/projects` | Bearer + member | List projects (`folderId`, `type=VIDEO\|PRESENTATION` optional) |
| GET | `/api/workspaces/:workspaceId/projects/:projectId` | Bearer + member | Get project |
| PATCH | `/api/workspaces/:workspaceId/projects/:projectId` | Bearer + member | Update project metadata |
| PATCH | `/api/workspaces/:workspaceId/projects/:projectId/data` | Bearer + member | Save validated editor state |
| POST | `/api/workspaces/:workspaceId/projects/:projectId/scenes/from-template` | Bearer + member | Append scene from VIDEO_SCENE template |
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
| GET | `/api/assets/:workspaceId` | Bearer + workspace access | List workspace assets (`take` / `skip`, optional `source=upload\|stock\|ai_gen\|all`) |
| PATCH | `/api/assets/:workspaceId/:assetId/rename` | Bearer + workspace access | Rename asset |
| DELETE | `/api/assets/:workspaceId/:assetId` | Bearer + workspace access | Delete asset |
| GET | `/api/stock/search` | Bearer | Search stock (`q`, `type=photo\|video`, `provider=pexels\|unsplash\|pixabay\|all`, `page`, `perPage`) |
| POST | `/api/stock/workspaces/:workspaceId/import` | Bearer + workspace access | Import stock item → workspace Asset (S3 copy) |
| GET | `/api/fonts/catalog` | Bearer | Font catalog + pairings (`q`, `category`, `subset`, `featured`, `limit`) |
| GET | `/api/fonts/css` | Bearer | Build Google Fonts CSS2 URL (`families`) |
| GET | `/api/graphics` | Bearer | Published SVG catalog (`q`, `category`, `type`, `page`, `limit`) |
| POST | `/api/graphics/search` | Bearer | Intent search over published graphics |
| GET | `/api/graphics/:id` | Bearer | One published graphic |
| GET | `/api/image-gen/models` | Bearer | Image Gen model picker catalog |
| GET | `/api/image-gen/formats` | Bearer | Image Gen format catalog (square / landscape / portrait) |
| GET | `/api/image-gen/styles` | Bearer | Image Gen vibe/style presets |
| GET | `/api/image-gen/workspaces/:workspaceId/estimate` | Bearer + workspace access | Image Gen credit estimate |
| POST | `/api/image-gen/workspaces/:workspaceId/context` | Bearer + workspace access | Create context bundle (multipart, free) |
| GET | `/api/image-gen/workspaces/:workspaceId/context/:contextId` | Bearer + workspace access | Get context preview |
| DELETE | `/api/image-gen/workspaces/:workspaceId/context/:contextId` | Bearer + workspace access | Delete unpinned context |
| POST | `/api/image-gen/workspaces/:workspaceId/generate` | Bearer + workspace access | Generate image (sync) → Asset + folder chat (`folderId` required) |
| GET | `/api/image-gen/workspaces/:workspaceId/threads` | Bearer + workspace access | List image chats (`folderId`/`take`/`skip`) |
| GET | `/api/image-gen/workspaces/:workspaceId/threads/:threadId` | Bearer + workspace access | Get chat + messages (free) |
| POST | `/api/image-gen/workspaces/:workspaceId/threads/:threadId/messages` | Bearer + workspace access | Chat send → tweak latest hop (charges) |
| PATCH | `/api/image-gen/workspaces/:workspaceId/threads/:threadId` | Bearer + workspace access | Rename chat |
| POST | `/api/image-gen/workspaces/:workspaceId/threads/:threadId/move-folder` | Bearer + workspace access | Move chat to another folder |
| DELETE | `/api/image-gen/workspaces/:workspaceId/threads/:threadId` | Bearer + workspace access | Delete chat (keeps assets) |
| GET | `/api/image-gen/workspaces/:workspaceId/generations` | Bearer + workspace access | List image hops (`take`/`skip`/`mode`/`threadId`) |
| GET | `/api/image-gen/workspaces/:workspaceId/generations/:generationId` | Bearer + workspace access | Get generation |
| POST | `/api/image-gen/workspaces/:workspaceId/generations/:generationId/regenerate` | Bearer + workspace access | Regenerate |
| POST | `/api/image-gen/workspaces/:workspaceId/generations/:generationId/tweak` | Bearer + workspace access | Tweak with instruction |
| GET | `/api/image-gen/workspaces/:workspaceId/generations/:generationId/download` | Bearer + workspace access | Download `png`\|`jpg`\|`jpeg`\|`pdf` |
| GET | `/api/credits/me` | Bearer | Personal credit balance |
| GET | `/api/credits/me/history` | Bearer | Personal credit ledger |
| GET | `/api/credits/me/estimate` | Bearer | Personal estimate (`voice_clone` \| `voice_design` \| `voice_preview` \| `avatar_create`) |
| GET | `/api/credits/:id` | Bearer + member | Workspace credit balance |
| GET | `/api/credits/:id/estimate` | Bearer + member | Workspace estimate (`heygen_video` \| `speech_generation` \| `remotion_export`) |
| POST | `/api/credits/:id/allocate` | Bearer + OWNER | TEAM: personal → workspace pool |
| POST | `/api/credits/:id/deallocate` | Bearer + OWNER | TEAM: workspace pool → personal |
| GET | `/api/credits/:id/history` | Bearer + OWNER/ADMIN | Workspace credit history |
| GET | `/api/credits/:id/my-history` | Bearer + any member | My credits in workspace |
| GET | `/api/credits/:id/usage-by-member` | Bearer + OWNER/ADMIN | TEAM usage by member |
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
| GET | `/api/superadmin/early-access/requests` | Bearer + platform superadmin | Early access request queue |
| GET | `/api/superadmin/early-access/requests/:requestId` | Bearer + platform superadmin | Single early access request |
| PATCH | `/api/superadmin/early-access/requests/:requestId/status` | Bearer + platform superadmin | Update status (`under_review`, `in_discussion`, `approved`, `rejected`) |
| POST | `/api/superadmin/early-access/requests/:requestId/approve` | Bearer + platform superadmin | Approve early access request |
| POST | `/api/superadmin/early-access/requests/:requestId/reject` | Bearer + platform superadmin | Reject early access request |
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
| GET | `/api/superadmin/broadcasts/product-email` | Bearer + platform superadmin | Product email broadcast history (paginated) |
| GET | `/api/superadmin/broadcasts/product-email/:broadcastId` | Bearer + platform superadmin | Single broadcast detail |
| GET | `/api/superadmin/broadcasts/product-email/:broadcastId/recipients` | Bearer + platform superadmin | Per-recipient delivery log (`status` filter) |
| GET | `/api/superadmin/graphics` | Bearer + platform superadmin | List graphics library |
| POST | `/api/superadmin/graphics` | Bearer + platform superadmin | Upload SVG (starts as draft) |
| GET | `/api/superadmin/graphics/:id` | Bearer + platform superadmin | Get graphic |
| PATCH | `/api/superadmin/graphics/:id` | Bearer + platform superadmin | Update metadata |
| POST | `/api/superadmin/graphics/:id/publish` | Bearer + platform superadmin | Publish |
| POST | `/api/superadmin/graphics/:id/unpublish` | Bearer + platform superadmin | Back to draft |
| POST | `/api/superadmin/graphics/:id/archive` | Bearer + platform superadmin | Archive |
| DELETE | `/api/superadmin/graphics/:id` | Bearer + platform superadmin | Delete + S3 |
| GET | `/api/superadmin/graphics/getillustrations/meta` | Bearer + platform superadmin | GetIllustrations categories/packs |
| GET | `/api/superadmin/graphics/getillustrations/free` | Bearer + platform superadmin | Browse free GetIllustrations catalog |
| POST | `/api/superadmin/graphics/getillustrations/icon-packs/:packId/save` | Bearer + platform superadmin | Import icon pack into library |
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

