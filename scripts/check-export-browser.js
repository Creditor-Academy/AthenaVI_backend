/**
 * Launch the PDF / image export browser and render a test page. Exits 1 if it can't, so a
 * Docker build without a working browser fails at build time instead of in production.
 */
const { checkExportBrowser } = require('../src/shared/utils/exportBrowser');

checkExportBrowser()
  .then((check) => {
    console.log(JSON.stringify(check, null, 2));
    process.exit(check.ok ? 0 : 1);
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
