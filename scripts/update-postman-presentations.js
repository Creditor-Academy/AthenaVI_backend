const fs = require('fs');
const path = require('path');

// Collection is Postman v3 YAML under postman/collections/AthenaVI Backend/.
// This script still targets the legacy single-file JSON format and needs a rewrite.
throw new Error(
  'update-postman-presentations.js is outdated: edit YAML under postman/collections/AthenaVI Backend/Presentations (AI PPT)/ instead'
);

const collectionPath = path.join(__dirname, '../postman/AthenaVI_Backend.postman_collection.json');
const col = JSON.parse(fs.readFileSync(collectionPath, 'utf8'));

function url(pathParts) {
  return {
    raw: `{{baseUrl}}/${pathParts.join('/')}`,
    host: ['{{baseUrl}}'],
    path: pathParts,
  };
}

const authHeader = { key: 'Authorization', value: 'Bearer {{accessToken}}' };
const jsonHeader = { key: 'Content-Type', value: 'application/json' };

const folder = {
  name: 'Presentations (AI PPT)',
  description:
    'Isolated presentation module under /api/workspaces/:workspaceId/presentations. Separate OpenAI credits from HeyGen/video.',
  item: [
    {
      name: 'Create presentation',
      request: {
        method: 'POST',
        header: [authHeader, jsonHeader],
        body: {
          mode: 'raw',
          raw: '{\n  "title": "Q3 Pitch",\n  "folderId": "{{folderId}}"\n}',
        },
        url: url(['workspaces', '{{workspaceId}}', 'presentations']),
      },
    },
    {
      name: 'Generate outline',
      request: {
        method: 'POST',
        header: [authHeader, jsonHeader],
        body: {
          mode: 'raw',
          raw: '{\n  "source": "prompt",\n  "prompt": "Pitch deck for Athena VI",\n  "slideCount": 10,\n  "density": "balanced",\n  "locale": "en"\n}',
        },
        url: url([
          'workspaces',
          '{{workspaceId}}',
          'presentations',
          '{{presentationId}}',
          'outline',
        ]),
      },
    },
    {
      name: 'Set theme',
      request: {
        method: 'POST',
        header: [authHeader, jsonHeader],
        body: {
          mode: 'raw',
          raw: '{\n  "themeId": "midnight_blue"\n}',
        },
        url: url([
          'workspaces',
          '{{workspaceId}}',
          'presentations',
          '{{presentationId}}',
          'theme',
        ]),
      },
    },
    {
      name: 'Generate deck',
      request: {
        method: 'POST',
        header: [authHeader, jsonHeader],
        body: {
          mode: 'raw',
          raw: '{\n  "density": "balanced",\n  "overwriteManualEdits": false\n}',
        },
        url: url([
          'workspaces',
          '{{workspaceId}}',
          'presentations',
          '{{presentationId}}',
          'generate',
        ]),
      },
    },
    {
      name: 'Get status',
      request: {
        method: 'GET',
        header: [authHeader],
        url: url([
          'workspaces',
          '{{workspaceId}}',
          'presentations',
          '{{presentationId}}',
          'status',
        ]),
      },
    },
    {
      name: 'Get presentation',
      request: {
        method: 'GET',
        header: [authHeader],
        url: url(['workspaces', '{{workspaceId}}', 'presentations', '{{presentationId}}']),
      },
    },
    {
      name: 'Credit estimate',
      request: {
        method: 'GET',
        header: [authHeader],
        url: url([
          'workspaces',
          '{{workspaceId}}',
          'presentations',
          '{{presentationId}}',
          'credit-estimate',
        ]),
      },
    },
    {
      name: 'Export PPTX',
      request: {
        method: 'POST',
        header: [authHeader, jsonHeader],
        body: {
          mode: 'raw',
          raw: '{\n  "format": "PPTX"\n}',
        },
        url: url([
          'workspaces',
          '{{workspaceId}}',
          'presentations',
          '{{presentationId}}',
          'export',
        ]),
      },
    },
    {
      name: 'Get export',
      request: {
        method: 'GET',
        header: [authHeader],
        url: url([
          'workspaces',
          '{{workspaceId}}',
          'presentations',
          '{{presentationId}}',
          'export',
          '{{exportId}}',
        ]),
      },
    },
  ],
};

const idx = col.item.findIndex((i) => i.name === 'Presentations (AI PPT)');
if (idx >= 0) col.item[idx] = folder;
else col.item.push(folder);

const vars = col.variable || [];
for (const v of [
  { key: 'presentationId', value: '' },
  { key: 'exportId', value: '' },
]) {
  if (!vars.some((x) => x.key === v.key)) vars.push(v);
}
col.variable = vars;

fs.writeFileSync(collectionPath, JSON.stringify(col, null, 2));
console.log('Postman Presentations folder updated');
