const { ensureBrowser } = require('@remotion/renderer');

ensureBrowser()
  .then(() => {
    console.log('Chrome Headless Shell ready');
    process.exit(0);
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
