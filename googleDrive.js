const fs = require('fs');
const { google } = require('googleapis');

const SCOPES = ['https://www.googleapis.com/auth/drive.file'];
const TOKEN_PATH = 'token.json';

const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

if (fs.existsSync(TOKEN_PATH)) {
  const token = JSON.parse(fs.readFileSync(TOKEN_PATH));
  oAuth2Client.setCredentials(token);
}

// สร้าง folder สำหรับ property
async function createPropertyFolder(name, id) {
  const drive = google.drive({ version: 'v3', auth: oAuth2Client });
  const folderName = `${name.replace(/\s+/g, '_')}_${id}`;

  const fileMetadata = {
    name: folderName,
    mimeType: 'application/vnd.google-apps.folder'
  };

  const folder = await drive.files.create({
    resource: fileMetadata,
    fields: 'id,name'
  });

  return folder.data.id; // เก็บ folderId เพื่อใช้ upload ไฟล์
}

// อัปโหลดไฟล์เข้า folder
async function uploadFileToFolder(file, folderId) {
  const drive = google.drive({ version: 'v3', auth: oAuth2Client });
  const timestamp = Date.now();
  const extension = file.originalname.substring(file.originalname.lastIndexOf('.')) || '.jpg';
  const fileName = `${timestamp}${extension}`;

  const res = await drive.files.create({
    requestBody: {
      name: fileName,
      parents: [folderId]  // ส่งเข้า folder เฉพาะ
    },
    media: { mimeType: file.mimetype, body: fs.createReadStream(file.path) },
    fields: 'id,name'
  });

  // ตั้งสิทธิ์ public
  await drive.permissions.create({
    fileId: res.data.id,
    requestBody: { role: 'reader', type: 'anyone' },
  });

  fs.unlinkSync(file.path); // ลบไฟล์ temp
  return `https://drive.google.com/uc?id=${res.data.id}`;
}

module.exports = { createPropertyFolder, uploadFileToFolder };
