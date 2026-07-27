const fs = require('fs');
const path = require('path');

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
  name: 'Video templates',
  description:
    'VIDEO_SCENE templates for the video editor only. Isolated from Presentations (AI PPT) / DECK_LAYOUT.',
  item: [
    {
      name: 'List video templates',
      request: {
        method: 'GET',
        header: [authHeader],
        url: url(['workspaces', '{{workspaceId}}', 'video-templates']),
      },
    },
    {
      name: 'Get video template',
      request: {
        method: 'GET',
        header: [authHeader],
        url: url(['workspaces', '{{workspaceId}}', 'video-templates', '{{videoTemplateId}}']),
      },
    },
    {
      name: 'Create project from template',
      request: {
        method: 'POST',
        header: [authHeader, jsonHeader],
        body: {
          mode: 'raw',
          raw: '{\n  "title": "From video template",\n  "folderId": "{{folderId}}",\n  "aspectRatio": "16:9",\n  "templateId": "{{videoTemplateId}}"\n}',
        },
        url: url(['workspaces', '{{workspaceId}}', 'projects']),
      },
    },
    {
      name: 'Append scene from template',
      request: {
        method: 'POST',
        header: [authHeader, jsonHeader],
        body: {
          mode: 'raw',
          raw: '{\n  "templateId": "{{videoTemplateId}}"\n}',
        },
        url: url([
          'workspaces',
          '{{workspaceId}}',
          'projects',
          '{{projectId}}',
          'scenes',
          'from-template',
        ]),
      },
    },
  ],
};

const idx = col.item.findIndex((i) => i.name === 'Video templates');
if (idx >= 0) col.item[idx] = folder;
else col.item.push(folder);

const vars = col.variable || [];
if (!vars.some((x) => x.key === 'videoTemplateId')) {
  vars.push({ key: 'videoTemplateId', value: '' });
}
col.variable = vars;

fs.writeFileSync(collectionPath, JSON.stringify(col, null, 2));
console.log('Postman Video templates folder updated');
