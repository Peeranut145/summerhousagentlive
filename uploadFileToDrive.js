const { google } = require('googleapis');
const fs = require('fs');

async function uploadFileToDrive(filePath, fileName, mimeType, parentFolderId) {
  const auth = new google.auth.GoogleAuth({
    keyFile: 'service-account.json',
    scopes: ['https://www.googleapis.com/auth/drive.file']
  });

  const drive = google.drive({ version: 'v3', auth });

  // ถ้า parentFolderId มี ให้อัปโหลดเข้า folder นั้น
  const res = await drive.files.create({
    requestBody: {
      name: fileName,
      parents: parentFolderId ? [parentFolderId] : [],
    },
    media: {
      mimeType,
      body: fs.createReadStream(filePath)
    },
    fields: 'id, name'
  });

  // ตั้งสิทธิ์ public
  await drive.permissions.create({
    fileId: res.data.id,
    requestBody: { role: 'reader', type: 'anyone' },
  });

  const url = `https://drive.google.com/uc?id=${res.data.id}`;
  fs.unlinkSync(filePath); // ลบไฟล์ชั่วคราว
  return url;
}
async function createFolder(folderName, parentFolderId) {
  const auth = new google.auth.GoogleAuth({
    keyFile: 'service-account.json',
    scopes: ['https://www.googleapis.com/auth/drive.file']
  });
  const drive = google.drive({ version: 'v3', auth });

  const res = await drive.files.create({
    requestBody: {
      name: folderName,
      mimeType: 'application/vnd.google-apps.folder',
      parents: parentFolderId ? [parentFolderId] : [],
    },
    fields: 'id, name'
  });

  return res.data.id;
}
