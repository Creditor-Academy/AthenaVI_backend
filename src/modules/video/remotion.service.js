const path = require("path");
const fs = require("fs");
const {bundle} = require("@remotion/bundler");
const { renderMedia } = require("@remotion/renderer");

let bundleLocation = null;

async function renderScene({ text, duration }) {
  console.log('remotion start');
  
  const entry = path.resolve("src/remotion/index.ts");
  console.log('remotion done');
  

  if (!bundleLocation) {
    bundleLocation = await bundle(entry);
  }

  const fps = 30;
  const durationInFrames = Math.ceil((duration + 0.5) * fps);

  const outputDir = path.resolve("renders");

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir);
  }

  const outputLocation = path.join(
    outputDir,
    `scene-${Date.now()}.mp4`
  );

  const renderPromise = renderMedia({
    composition: "Scene",
    serveUrl: bundleLocation,
    codec: "h264",
    outputLocation,
    inputProps: { text },
    durationInFrames,
    fps,
  });
  console.log(renderPromise);
  

  return outputLocation;
}


module.exports = {
    renderScene
}