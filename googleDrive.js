const fs = require('fs');
const { google } = require('googleapis');

const SCOPES = ['https://www.googleapis.com/auth/drive.file'];
const TOKEN_PATH = 'token.json'; // เก็บ token หลัง authorize

const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// โหลด token ถ้ามี
if (fs.existsSync(TOKEN_PATH)) {
  const token = JSON.parse(fs.readFileSync(TOKEN_PATH));
  oAuth2Client.setCredentials(token);
}

// ฟังก์ชัน upload ไฟล์
async function uploadFile(file) {
  const drive = google.drive({ version: 'v3', auth: oAuth2Client });

  // ตั้งชื่อไฟล์ใหม่ กันซ้ำ
  const timestamp = Date.now();
  const extension = file.originalname.substring(file.originalname.lastIndexOf('.')) || '.jpg';
  const fileName = `${timestamp}${extension}`;

  const res = await drive.files.create({
    requestBody: { name: fileName },
    media: { mimeType: file.mimetype, body: fs.createReadStream(file.path) },
    fields: 'id,name',
  });

  // ตั้งสิทธิ์ public
  await drive.permissions.create({
    fileId: res.data.id,
    requestBody: { role: 'reader', type: 'anyone' },
  });

  const url = `https://drive.google.com/uc?id=${res.data.id}`;
  fs.unlinkSync(file.path); // ลบไฟล์ชั่วคราว
  return url;
}

module.exports = { uploadFile };
