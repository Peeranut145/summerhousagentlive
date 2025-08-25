const { google } = require('googleapis');
const fs = require('fs');

const credentials = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_KEY);
const auth = new google.auth.GoogleAuth({
  credentials,
  scopes: ['https://www.googleapis.com/auth/drive.file'],
});
const drive = google.drive({ version: 'v3', auth });

async function uploadFileToDrive(path, name, mimeType, folderId = null) {
  const fileMetadata = { name };
  if (folderId) fileMetadata.parents = [folderId];

  const res = await drive.files.create({
    requestBody: fileMetadata,
    media: { mimeType, body: fs.createReadStream(path) },
    fields: 'id,name',
  });

  await drive.permissions.create({
    fileId: res.data.id,
    requestBody: { role: 'reader', type: 'anyone' },
  });

  fs.unlinkSync(path);
  return `https://drive.google.com/uc?id=${res.data.id}`;
}

async function createFolder(name, parentId = null) {
  const fileMetadata = { name, mimeType: 'application/vnd.google-apps.folder' };
  if (parentId) fileMetadata.parents = [parentId];

  const res = await drive.files.create({
    requestBody: fileMetadata,
    fields: 'id'
  });

  return res.data.id;
}

module.exports = { uploadFileToDrive, createFolder };
