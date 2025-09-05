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
const cloudinary = require('cloudinary').v2;
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

//----------------------------------------------------
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
async function uploadToCloudinary(filePath, folder = "properties") {
  try {
    const result = await cloudinary.uploader.upload(filePath, {
      folder: folder,   // เก็บในโฟลเดอร์ properties
      resource_type: "image"
    });
    return result.secure_url; // เอา URL ไปเก็บใน DB
  } catch (err) {
    console.error("Cloudinary upload error:", err);
    throw err;
  }
}

module.exports = { uploadToCloudinary };

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


//------------------------Fav-------------------------------

// ✅ GET favorites by user
app.get('/api/favorites/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query(
      `SELECT p.*
       FROM favorites f
       JOIN properties p ON f.property_id = p.property_id
       WHERE f.user_id = $1`,
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching favorites:', err);
    res.status(500).json({ error: err.message });
  }
});


// ✅ ADD favorite
app.post('/api/favorites', async (req, res) => {
  try {
    const { user_id, property_id } = req.body;
    await pool.query(
      `INSERT INTO favorites (user_id, property_id)
       VALUES ($1, $2)
       ON CONFLICT (user_id, property_id) DO NOTHING`,
      [user_id, property_id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Error adding favorite:', err);
    res.status(500).json({ error: err.message });
  }
});


// ✅ REMOVE favorite
app.delete('/api/favorites/:userId/:propertyId', async (req, res) => {
  try {
    const { userId, propertyId } = req.params;
    await pool.query(
      `DELETE FROM favorites WHERE user_id = $1 AND property_id = $2`,
      [userId, propertyId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting favorite:', err);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------- Properties ----------------------
// Get all properties
// Get all properties
app.get('/api/properties', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
    property_id, name, price, location, type, status, description,
    images,
        bedrooms, bathrooms, swimming_pool, building_area, land_area,
        ownership, construction_status, floors, furnished, parking,
        is_featured, created_at, contact_info,
    FROM properties
    WHERE status=$1 OR status=$2

    `, ['Buy', 'Rent']);
    res.json(result.rows);  // images จะเป็น array ของ JS เลย
  } catch (err) {
    console.error('Properties fetch error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});



app.get('/api/properties/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(`
      SELECT 
          property_id AS "propertyId",
          name,
          price,
          location,
          type,
          status,
          description,
          COALESCE(images, ARRAY[]::text[]) AS images,
          bedrooms,
          bathrooms,
          swimming_pool AS "swimmingPool",
          building_area AS "buildingArea",
          land_area AS "landArea",
          ownership,
          construction_status AS "constructionStatus",
          floors,
          furnished,
          parking,
          is_featured AS "isFeatured",
          created_at AS "createdAt",
          updated_at AS "updatedAt",
          user_id AS "userId",
          contact_info AS "contactInfo"
        FROM properties
        WHERE property_id = $1;


    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Property not found' });
    }

    console.log("Property result:", result.rows[0]); // ✅ debug ตรงนี้
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Property fetch error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});



app.post('/api/properties', upload.array('images'), async (req, res) => {
  const data = req.body;
  let cloudinaryUrls = []; // เก็บ URL จาก Cloudinary

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
    const contact_info = data.contact_info || null;

    // อัปโหลดขึ้น Cloudinary
    if (req.files && req.files.length > 0) {
      for (let file of req.files) {
        try {
          const url = await uploadToCloudinary(file.path, "properties");
          cloudinaryUrls.push(url);
        } catch (err) {
          console.error("Cloudinary upload error:", err);
        }
      }
    }

    // บันทึกลง DB (images[] type text)
    const result = await pool.query(`
      INSERT INTO properties
          (user_id, name, price, location, type, status, description, images,
          bedrooms, bathrooms, swimming_pool, building_area, land_area,
          ownership, construction_status, floors, furnished, parking,
          is_featured, contact_info, created_at)
      VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8,
          $9, $10, $11, $12, $13,
          $14, $15, $16, $17, $18,
          $19, $20, NOW())
      RETURNING *;

    `, [
      user_id,
      data.name,
      price,
      data.location,
      data.type || null,
      data.status || null,
      data.description || null,
      cloudinaryUrls.length > 0 ? cloudinaryUrls : null, // 👈 ส่งเป็น array ตรง ๆ
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
      contact_info
    ]);

    res.status(201).json({
      message: 'Property added',
      property: result.rows[0],
      images: cloudinaryUrls // ส่ง URL กลับ frontend
    });

  } catch (err) {
    console.error('Property insert error:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// Update property with images
app.put('/api/properties/:id', upload.array('images'), async (req, res) => {
  const { id } = req.params;
  const {
    name, price, location, type, status, description, contact_info,
    bedrooms, bathrooms, swimming_pool, building_area, land_area,
    ownership, construction_status, floors, furnished, parking,
    is_featured,
    removedImages
  } = req.body;

  try {
    // 1. ดึงรูปเดิมจาก DB
    const result = await pool.query(
      'SELECT images FROM properties WHERE property_id=$1',
      [id]
    );
    let currentImages = result.rows[0]?.images || [];

    // 2. ลบรูปที่เลือก
    if (removedImages) {
      const removed = JSON.parse(removedImages);
      currentImages = currentImages.filter(img => !removed.includes(img));
    }

    // 3. เพิ่มรูปใหม่
    if (req.files && req.files.length > 0) {
      const newImageUrls = req.files.map(file => `/uploads/${file.filename}`);
      currentImages = [...currentImages, ...newImageUrls];
    }

    // 4. อัปเดตฟิลด์ทั้งหมด
    const updateQuery = `
      UPDATE properties SET
        name=$1,
        price=$2,
        location=$3,
        type=$4,
        status=$5,
        description=$6,
        contact_info=$7,
        images=$8,
        bedrooms=$9,
        bathrooms=$10,
        swimming_pool=$11,
        building_area=$12,
        land_area=$13,
        ownership=$14,
        construction_status=$15,
        floors=$16,
        furnished=$17,
        parking=$18,
        is_featured=$19,
        updated_at=NOW()
      WHERE property_id=$20
      RETURNING *;
    `;

    const values = [
      name, price, location, type, status, description, contact_info,
      currentImages,
      bedrooms, bathrooms, swimming_pool, building_area, land_area,
      ownership, construction_status, floors, furnished, parking, is_featured,
      id
    ];

    const updated = await pool.query(updateQuery, values);

    res.json({ message: 'Property updated successfully', property: updated.rows[0] });

  } catch (err) {
    console.error('Property update error:', err);
    res.status(500).json({ error: 'Internal server error' });
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
