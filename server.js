require('dotenv').config();
const express = require('express');
const fs = require('fs');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { createFolder, uploadFileToDrive } = require('./drive');
const app = express();
const port = process.env.PORT || 5000;

// ---------------------- Database ----------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.query('SELECT NOW()', (err, res) => {
  if(err) console.error(err);
  else console.log('PostgreSQL live time:', res.rows[0]);
});

// ---------------------- Middleware ----------------------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(morgan('combined'));

// Rate limiter แบบ global
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, try again later.'
});
app.use(generalLimiter);

// Rate limiter แยกสำหรับ login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: "Too many login attempts. Try again later." }
});

// ---------------------- Multer Setup ----------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, '../frontend/public/uploads');
    if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Serve static uploads
app.use('/uploads', express.static(path.join(__dirname, '../frontend/public/uploads')));

// ---------------------- Nodemailer ----------------------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ---------------------- Auth Routes ----------------------

// Register
app.post('/api/register', async (req, res) => {
  const { username, email, password, phone_number, role = 'user' } = req.body;
  if (!username || !email || !password || !phone_number) return res.status(400).json({ success: false, message: 'Missing required fields' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, email, password, phone_number, role)
       VALUES ($1, $2, $3, $4, $5) RETURNING user_id`,
      [username, email, hashedPassword, phone_number, role]
    );
    res.status(201).json({ success: true, message: 'User registered', userId: result.rows[0].user_id });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ success: false, message: 'Error registering user' });
  }
});

// Login
app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: 'Missing username or password' });

  try {
    const result = await pool.query('SELECT * FROM users WHERE username=$1 OR email=$2', [username, username]);
    if (result.rows.length === 0) return res.status(400).json({ success: false, message: 'Invalid username or password' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ success: false, message: 'Invalid username or password' });

    const token = jwt.sign({ userId: user.user_id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ success: true, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ---------------------- Password Reset ----------------------
app.post('/api/request-reset-password', async (req, res) => {
  const { email } = req.body;
  try {
    const userResult = await pool.query('SELECT user_id, email FROM users WHERE email=$1', [email]);
    if (userResult.rows.length === 0) return res.status(400).json({ success: false, message: 'Email not found' });

    const user = userResult.rows[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    await pool.query(`
      INSERT INTO reset_tokens (user_id, token, expires_at)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id) DO UPDATE SET token=$2, expires_at=$3
    `, [user.user_id, token, expiresAt]);

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Password Reset',
      html: `<p>Click the link to reset your password (expires in 1h):</p><a href="${resetUrl}">${resetUrl}</a>`
    });
    res.json({ success: true, message: 'Reset link sent' });
  } catch (err) {
    console.error('Reset request error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Reset by token
app.post('/api/reset-password-by-token', async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const result = await pool.query('SELECT user_id, expires_at FROM reset_tokens WHERE token=$1', [token]);
    if (result.rows.length === 0 || new Date() > result.rows[0].expires_at) return res.status(400).json({ success: false, message: 'Invalid or expired token' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password=$1 WHERE user_id=$2', [hashed, result.rows[0].user_id]);
    await pool.query('DELETE FROM reset_tokens WHERE user_id=$1', [result.rows[0].user_id]);
    res.json({ success: true, message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ---------------------- Properties ----------------------

// Get all properties
app.get('/api/properties', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        property_id, name, price, location, type, status, description,
        COALESCE(to_json(image), '[]') AS image,
        bedrooms, bathrooms, swimming_pool, building_area, land_area,
        ownership, construction_status, floors, furnished, parking,
        is_featured, created_at
      FROM properties
      WHERE status=$1 OR status=$2
    `, ['Buy', 'Rent']);
    res.json(result.rows);
  } catch (err) {
    console.error('Properties fetch error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get property by ID
app.get('/api/properties/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(`
      SELECT 
        property_id, name, price, location, type, status, description,
        COALESCE(to_json(image), '[]') AS image,
        bedrooms, bathrooms, swimming_pool, building_area, land_area,
        ownership, construction_status, floors, furnished, parking,
        is_featured, created_at
      FROM properties
      WHERE property_id=$1
    `, [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Property not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Property fetch error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/properties', upload.array('images'), async (req, res) => {
  const data = req.body;
  let imageFilenames = []; // สำหรับเก็บชื่อไฟล์ใน frontend
  let driveUrls = [];      // สำหรับเก็บ URL จาก Google Drive

  try {
    const user_id = parseInt(data.user_id) || 1;
    const price = parseFloat(data.price) || 0;
    const bedrooms = parseInt(data.bedrooms) || 0;
    const bathrooms = parseInt(data.bathrooms) || 0;
    const is_featured = data.is_featured === 'true';
    const swimming_pool = data.swimming_pool === 'true';
    const floors = parseInt(data.floors) || 1;
    const furnished = data.furnished === 'true';
    const parking = parseInt(data.parking) || 0;
    const contact_info = data.contact_info === 'true';

    // สร้างโฟลเดอร์บน Google Drive
    const folderName = `${data.name}-${Date.now()}`;
    const folderData = await createFolder(folderName, process.env.GOOGLE_DRIVE_PARENT_FOLDER_ID);
    const folderId = folderData.id;

    // อัปโหลดไฟล์
    if (req.files && req.files.length > 0) {
      for (let file of req.files) {
        // 1️⃣ copy ไป frontend/public/uploads/
        const destPath = path.join(__dirname, '../frontend/public/uploads/', file.filename);
        fs.copyFileSync(file.path, destPath);
        imageFilenames.push(file.filename);

        // 2️⃣ อัปโหลดไป Google Drive
        try {
          const url = await uploadFileToDrive(file.path, file.originalname, file.mimetype, folderId);
          driveUrls.push(url);
        } catch (err) {
          console.error('Upload to Drive error:', err);
        }
      }
    }

  // insert DB (เก็บทั้ง local filename + drive urls เป็น JSON)
const result = await pool.query(`
  INSERT INTO properties
    (user_id, name, price, location, type, status, description, image,
     drive_urls, bedrooms, bathrooms, swimming_pool, building_area, land_area,
     ownership, construction_status, floors, furnished, parking,
     is_featured, contact_info, created_at)
  VALUES
    ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,NOW())
  RETURNING *;
`, [
  user_id,
  data.name,
  price,
  data.location,
  data.type || null,
  data.status || null,
  data.description || null,
  imageFilenames.length > 0 ? JSON.stringify(imageFilenames) : null,
  driveUrls.length > 0 ? JSON.stringify(driveUrls) : null,
  bedrooms,
  bathrooms,
  swimming_pool,
  data.building_area ? parseFloat(data.building_area) : null,
  data.land_area ? parseFloat(data.land_area) : null,
  data.ownership || null,
  data.construction_status || null,
  floors,
  furnished,
  parking,
  is_featured,
  data.contact_info || null
]);


    res.status(201).json({ 
      message: 'Property added', 
      property: result.rows[0],
      driveUrls
    });

  } catch (err) {
    console.error('Property insert error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});



// Update property
app.put('/api/properties/:id', async (req, res) => {
  try {
    const propertyId = req.params.id;
    const data = req.body;

    const query = `
      UPDATE properties SET
        name=$1,
        price=$2,
        location=$3,
        type=$4,
        status=$5,
        description=$6,
        contact_info=$7,
        construction_status=$8,
        bedrooms=$9,
        bathrooms=$10,
        is_featured=$11,
        swimming_pool=$12,
        building_area=$13,
        land_area=$14,
        ownership=$15,
        floors=$16,
        furnished=$17,
        parking=$18
      WHERE property_id=$19
    `;

    const values = [
      data.name,
      data.price,
      data.location,
      data.type,
      data.status,
      data.description,
      data.contact_info,
      data.construction_status,
      data.bedrooms,
      data.bathrooms,
      data.is_featured,
      data.swimming_pool,
      data.building_area,
      data.land_area,
      data.ownership,
      data.floors,
      data.furnished,
      data.parking,
      propertyId
    ];

    await pool.query(query, values);
    res.json({ success: true, message: "Property updated successfully" });
  } catch (err) {
    console.error("Property update error:", err);
    res.status(500).json({ error: "Failed to update property" });
  }
});




// DELETE property
app.delete('/api/properties/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM properties WHERE property_id=$1', [id]);
    if (result.rowCount === 0) return res.status(404).json({ success: false, message: 'Property not found' });
    res.json({ success: true, message: 'Property deleted' });
  } catch (err) {
    console.error('Property delete error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});



app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
