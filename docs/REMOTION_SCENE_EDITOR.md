# Using Remotion with the scene-based editor

If the video is **rendered with Remotion** (React-based programmatic video), the same Video/Scene model and payload still apply. Remotion consumes your scenes as **input props** to a composition. This doc describes what is needed for the video editor feature.

---

## 1. How Remotion fits in

- **Remotion** = React compositions that render to video. A composition has `id`, `width`, `height`, `fps`, `durationInFrames`, and accepts **inputProps** (JSON).
- Your **scenes** (order, duration, payload) become the data driving the composition: e.g. `inputProps = { scenes: scenesFromDB }`. The Remotion app defines a root composition that maps each scene to a `<Sequence>` (from / durationInFrames) and passes each scene's `payload` as props to the scene component.
- **Preview:** The frontend can use Remotion's **`<Player>`** with the same composition and the same `inputProps` (video + scenes from your API). No backend render needed for preview.
- **Final video:** Backend (or a dedicated render service) runs Remotion's server-side APIs: `bundle()` then `selectComposition()` then `renderMedia()` with `inputProps`; then upload the output to S3 and expose a URL.

So: **editor and payload stay the same**; you add a Remotion app (composition + sequences) and a backend render pipeline that uses that composition.

---

## 2. Where the Remotion code lives

- **Option A – Frontend repo:** The Remotion project (compositions, `<Sequence>` layout) lives in the same repo as the editor. Editor uses `<Player>` for preview; for Generate, the frontend calls your backend; the **backend** (or a worker) needs access to the Remotion bundle (e.g. built artifact or a separate clone) to run `renderMedia()`.
- **Option B – Separate Remotion repo:** A dedicated video-templates or remotion repo contains only the Remotion project. Backend (or a render service) clones/bundles that repo and runs `renderMedia()` with `inputProps` from your API. Frontend video editor fetches video+scenes from your API and either embeds Remotion Player (if the composition is shipped with the frontend for preview) or gets a preview URL from the backend.

Either way, the **backend** (this repo) still owns: Video/Scene CRUD, render job queue, and (optionally) the process that calls Remotion and uploads the result.

---

## 3. Remotion composition contract (inputProps)

The composition that represents one video should accept the same shape the backend returns for **video + scenes** (or a minimal subset). For example:

```ts
interface RemotionInputProps {
  scenes: Array<{
    id: string;
    order: number;
    startTime: number;
    duration: number;
    payload: {
      scriptText: string;
      avatar: string;
      avatarSettings?: { style?: string; voice?: string; scale?: number; horizontalAlign?: string };
      background: string;
      backgroundSettings?: { scale?: number };
      transition?: string;
    };
  }>;
  aspectRatio?: string;
}
```

- **Total duration:** Sum of `scenes[].duration` (or derive in Remotion via `calculateMetadata()`).
- **Per-scene:** Use `<Sequence from={frameFor(startTime)} durationInFrames={secondsToFrames(duration)}>` and pass `scene.payload` to your scene component. The **payload** the frontend sends (see main plan section 6) is exactly what Remotion receives per scene.

---

## 4. Backend: render pipeline (implemented)

The following is implemented in this backend:

| Piece | Status |
|-------|--------|
| **Render job model** | `RenderJob` in Prisma: `id`, `videoId`, `workspaceId`, `userId`, `status` (PENDING / RENDERING / COMPLETED / FAILED), `outputUrl`, `error`, timestamps. |
| **Job queue** | Bull queue `video-render` using Redis (`REDIS_URL`). |
| **Render worker** | `src/workers/render.worker.js` – loads video + scenes, builds `inputProps`, then calls `RENDER_SERVICE_URL` (POST with `{ inputProps }`, expects `{ outputUrl }`) or completes as stub with `outputUrl` null. Run with `npm run worker:render`. |
| **APIs** | `POST /api/workspaces/:id/videos/:videoId/render` – enqueue job, return `{ job }`. `GET /api/workspaces/:id/render/:jobId` – return job status and `outputUrl` when completed. |
| **Remotion / external render** | Set `RENDER_SERVICE_URL` to a service that accepts POST `{ inputProps }` and returns `{ outputUrl }` (e.g. Remotion Lambda or a small Node service that runs `bundle` → `renderMedia` and uploads to S3). |

No change to Video/Scene payload shape; the same request/response bodies work. Only the **consumer** of that data is Remotion or your render service.

---

## 5. Frontend with Remotion

- **Preview:** Load video + scenes from your API. Pass them as `inputProps` to Remotion's `<Player>` with the same composition ID used for render. Preview runs in the browser.
- **Generate:** Call `POST .../videos/:videoId/render`, then poll `GET .../render/:jobId` until `status === 'completed'`; show `outputUrl` for download or play.

---

## 6. Summary

- **Data model and APIs:** Unchanged – Video/Scene CRUD and payload for the video editor (see README).
- **Remotion app:** One composition accepting `inputProps = { scenes, aspectRatio }`; render `<Sequence>` per scene with `payload` as props.
- **Backend additions:** Render job model + queue + worker (Remotion `bundle` → `selectComposition` → `renderMedia`) + upload to S3; APIs to start render and poll job status.
- **Frontend:** Remotion Player with same `inputProps` for preview; render API + poll for final video.
