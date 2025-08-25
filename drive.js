const fs = require('fs');
const { google } = require('googleapis');
require('dotenv').config();

const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// ใส่ refresh token จากขั้นตอนดึง token
oAuth2Client.setCredentials({ refresh_token: process.env.GOOGLE_REFRESH_TOKEN });

// สร้าง service drive
async function getDriveService() {
  return google.drive({ version: 'v3', auth: oAuth2Client });
}

// upload file
async function uploadFileToDrive(filePath, fileName, mimeType, folderId = null) {
  const drive = await getDriveService();

  const fileMetadata = { name: fileName };
  if (folderId) fileMetadata.parents = [folderId];

  const media = { mimeType, body: fs.createReadStream(filePath) };

  const res = await drive.files.create({
    requestBody: fileMetadata,
    media,
    fields: 'id,name',
    supportsAllDrives: false
  });

  fs.unlinkSync(filePath); // ลบไฟล์ temp
  return `https://drive.google.com/uc?id=${res.data.id}`;
}

// create folder
async function createFolder(name, parentId = null) {
  const drive = await getDriveService();
  const fileMetadata = {
    name,
    mimeType: 'application/vnd.google-apps.folder'
  };
  if (parentId) fileMetadata.parents = [parentId];

  const res = await drive.files.create({
    requestBody: fileMetadata,
    fields: 'id,name',
    supportsAllDrives: false
  });

  return res.data; // {id, name}
}

module.exports = { uploadFileToDrive, createFolder };
