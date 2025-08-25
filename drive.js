const { google } = require('googleapis');
const fs = require('fs');

const credentials = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_KEY);

const auth = new google.auth.GoogleAuth({
  credentials,
  scopes: ['https://www.googleapis.com/auth/drive'],
});

async function getDriveService() {
  const client = await auth.getClient();
  return google.drive({ version: 'v3', auth: client });
}

// ✅ อัปโหลดไฟล์ไปยัง My Drive หรือ Shared Drive
async function uploadFileToDrive(path, name, mimeType, parentId = null, driveId = null) {
  const drive = await getDriveService();

  const fileMetadata = { name };
  if (parentId) fileMetadata.parents = [parentId];

  const res = await drive.files.create({
    requestBody: fileMetadata,
    media: { mimeType, body: fs.createReadStream(path) },
    fields: 'id,name',
    supportsAllDrives: true,
  });

  // ตั้งสิทธิ์ให้เปิดลิงก์ได้
  await drive.permissions.create({
    fileId: res.data.id,
    requestBody: { role: 'reader', type: 'anyone' },
    supportsAllDrives: true,
  });

  fs.unlinkSync(path);

  return `https://drive.google.com/uc?id=${res.data.id}`;
}

// ✅ สร้างโฟลเดอร์ใน My Drive หรือ Shared Drive
async function createFolder(name, parentId = null, driveId = null) {
  const drive = await getDriveService();

  const fileMetadata = {
    name,
    mimeType: 'application/vnd.google-apps.folder',
  };

  if (parentId) fileMetadata.parents = [parentId];
  if (driveId) fileMetadata.driveId = driveId;

  const res = await drive.files.create({
    requestBody: fileMetadata,
    fields: 'id,name',
    supportsAllDrives: true,
  });

  return res.data; // { id, name }
}

module.exports = { uploadFileToDrive, createFolder };
