const express = require('express');
const { google } = require('googleapis');

const app = express();
const PORT = process.env.PORT || 3000;

const SCOPES = ['https://www.googleapis.com/auth/drive.file'];

// สร้าง OAuth2 client
const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI // สามารถใส่ค่า Render URL หรือ localhost
);

// ✅ ใช้ refresh token จาก environment variable
oAuth2Client.setCredentials({
  refresh_token: process.env.GOOGLE_REFRESH_TOKEN
});

// ตัวอย่างฟังก์ชัน upload ไฟล์
async function uploadFile(filePath, fileName, mimeType) {
  const drive = google.drive({ version: 'v3', auth: oAuth2Client });

  const res = await drive.files.create({
    requestBody: { name: fileName },
    media: { mimeType, body: fs.createReadStream(filePath) },
    fields: 'id,name',
  });

  // ตั้งสิทธิ์ public อ่านได้
  await drive.permissions.create({
    fileId: res.data.id,
    requestBody: { role: 'reader', type: 'anyone' },
  });

  const url = `https://drive.google.com/uc?id=${res.data.id}`;
  return url;
}

// ตัวอย่าง route
app.get('/', (req, res) => res.send('Google Drive uploader running!'));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
