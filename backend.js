// server.js - Complete ERP + Razorpay Integration
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const Razorpay = require('razorpay');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use('/', express.static('uploads'));

// ✅ FIXED: Proper file serving
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ✅ FIXED: Single database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '2005',
  database: process.env.DB_NAME || 'erp_student_db'
});

db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err);
    process.exit(1);
  } else {
    console.log('Connected to MySQL database');
    createTables();
  }
});

// ✅ ADDED: Razorpay Configuration
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'YOUR_RAZORPAY_KEY_ID',
    key_secret: process.env.RAZORPAY_KEY_SECRET || 'YOUR_RAZORPAY_KEY_SECRET'
});

// Create tables if they don't exist
function createTables() {
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      user_id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      role ENUM('admin', 'teacher', 'student', 'parent') NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  const createStudentsTable = `
    CREATE TABLE IF NOT EXISTS students (
      student_id VARCHAR(20) PRIMARY KEY,
      user_id INT,
      first_name VARCHAR(50) NOT NULL,
      last_name VARCHAR(50) NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      phone VARCHAR(15),
      dob DATE,
      address TEXT,
      course_id INT,
      admission_date DATE,
      status ENUM('active', 'inactive', 'graduated', 'dropped') DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(user_id)
    )
  `;

  const createCoursesTable = `
    CREATE TABLE IF NOT EXISTS courses (
      course_id INT AUTO_INCREMENT PRIMARY KEY,
      course_name VARCHAR(100) NOT NULL,
      course_code VARCHAR(20) UNIQUE NOT NULL,
      credits INT DEFAULT 0,
      duration_years INT DEFAULT 4,
      fee_amount DECIMAL(10,2) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  const createAttendanceTable = `
    CREATE TABLE IF NOT EXISTS attendance (
      attendance_id INT AUTO_INCREMENT PRIMARY KEY,
      student_id VARCHAR(20),
      course_id INT,
      date DATE NOT NULL,
      status ENUM('present', 'absent', 'late') NOT NULL,
      marked_by INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (student_id) REFERENCES students(student_id),
      FOREIGN KEY (course_id) REFERENCES courses(course_id),
      FOREIGN KEY (marked_by) REFERENCES users(user_id)
    )
  `;

  const createFeesTable = `
    CREATE TABLE IF NOT EXISTS fees (
      fee_id INT AUTO_INCREMENT PRIMARY KEY,
      student_id VARCHAR(20),
      amount DECIMAL(10,2) NOT NULL,
      fee_type ENUM('tuition', 'hostel', 'transport', 'library', 'other') NOT NULL,
      due_date DATE NOT NULL,
      paid_date DATE NULL,
      status ENUM('pending', 'paid', 'overdue') DEFAULT 'pending',
      transaction_id VARCHAR(100) NULL,
      payment_method VARCHAR(50) NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (student_id) REFERENCES students(student_id)
    )
  `;

  const createHostelTable = `
    CREATE TABLE IF NOT EXISTS hostel (
      hostel_id INT AUTO_INCREMENT PRIMARY KEY,
      student_id VARCHAR(20),
      room_number VARCHAR(20) NOT NULL,
      block VARCHAR(10) NOT NULL,
      bed_number INT,
      allocated_date DATE,
      status ENUM('allocated', 'vacant', 'maintenance') DEFAULT 'allocated',
      monthly_fee DECIMAL(8,2) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (student_id) REFERENCES students(student_id)
    )
  `;

  const createNotificationsTable = `
    CREATE TABLE IF NOT EXISTS notifications (
      notification_id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      message TEXT NOT NULL,
      target_audience ENUM('all', 'students', 'teachers', 'parents', 'specific') DEFAULT 'all',
      created_by INT,
      is_urgent BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (created_by) REFERENCES users(user_id)
    )
  `;

  // Execute table creation
  db.query(createUsersTable, (err) => err && console.error('Users table error:', err));
  db.query(createStudentsTable, (err) => err && console.error('Students table error:', err));
  db.query(createCoursesTable, (err) => err && console.error('Courses table error:', err));
  db.query(createAttendanceTable, (err) => err && console.error('Attendance table error:', err));
  db.query(createFeesTable, (err) => err && console.error('Fees table error:', err));
  db.query(createHostelTable, (err) => err && console.error('Hostel table error:', err));
  db.query(createNotificationsTable, (err) => err && console.error('Notifications table error:', err));
}

// JWT middleware for authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// ============ RAZORPAY PAYMENT ROUTES ============

// Create Order Endpoint
app.post('/api/payment/create-order', async (req, res) => {
    try {
        const { amount, currency, studentId, feeType } = req.body;

        if (!amount || amount <= 0) {
            return res.status(400).json({ 
                success: false,
                error: 'Amount is required and must be greater than 0' 
            });
        }

        const options = {
            amount: amount * 100, // Amount in paisa
            currency: currency || 'INR',
            receipt: `receipt_${studentId || 'student'}_${Date.now()}`,
            notes: {
                student_id: studentId || 'N/A',
                fee_type: feeType || 'general',
                created_at: new Date().toISOString()
            }
        };

        console.log('Creating order with options:', options);

        const order = await razorpay.orders.create(options);
        
        console.log('✅ Order created successfully:', order.id);

        res.json({
            success: true,
            order_id: order.id,
            amount: order.amount,
            currency: order.currency,
            key_id: razorpay.key_id
        });

    } catch (error) {
        console.error('❌ Error creating order:', error);
        res.status(500).json({ 
            success: false,
            error: error.message || 'Failed to create order'
        });
    }
});

// Verify Payment Endpoint
app.post('/api/payment/verify-payment', (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
            return res.status(400).json({ 
                success: false,
                error: 'Missing payment verification data' 
            });
        }

        const body = razorpay_order_id + '|' + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac('sha256', razorpay.key_secret)
            .update(body.toString())
            .digest('hex');

        console.log('Expected Signature:', expectedSignature);
        console.log('Received Signature:', razorpay_signature);

        if (expectedSignature === razorpay_signature) {
            console.log('✅ Payment verified successfully:', razorpay_payment_id);
            
            // Update fee payment in database
            const updateFeeQuery = `
                UPDATE fees 
                SET status = 'paid', 
                    paid_date = CURRENT_DATE, 
                    transaction_id = ?, 
                    payment_method = 'razorpay' 
                WHERE student_id = ? AND status = 'pending'`;
            
            db.query(updateFeeQuery, [razorpay_payment_id, req.body.student_id], (err) => {
                if (err) console.error('Fee update error:', err);
            });
            
            res.json({ 
                success: true, 
                message: 'Payment verified successfully',
                payment_id: razorpay_payment_id,
                order_id: razorpay_order_id
            });
        } else {
            console.log('❌ Payment verification failed');
            res.status(400).json({ 
                success: false, 
                message: 'Payment verification failed' 
            });
        }

    } catch (error) {
        console.error('❌ Verification error:', error);
        res.status(500).json({ 
            success: false,
            error: error.message || 'Verification failed'
        });
    }
});

// ============ AUTH ROUTES ============

// Register user
app.post('/api/register', async (req, res) => {
  const { username, email, password, role } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)';
    
    db.query(query, [username, email, hashedPassword, role], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ error: 'Username or email already exists' });
        }
        return res.status(500).json({ error: 'Registration failed' });
      }
      res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login user
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  const query = 'SELECT * FROM users WHERE username = ? OR email = ?';
  db.query(query, [username, username], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = results[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.user_id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  });
});

// ============ STUDENT ROUTES ============

// Get all students (with pagination)
app.get('/api/students', authenticateToken, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  const query = `
    SELECT s.*, c.course_name, c.course_code 
    FROM students s 
    LEFT JOIN courses c ON s.course_id = c.course_id 
    ORDER BY s.created_at DESC 
    LIMIT ? OFFSET ?
  `;

  db.query(query, [limit, offset], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch students' });
    }

    db.query('SELECT COUNT(*) as total FROM students', (err, countResult) => {
      const total = countResult[0]?.total || 0;
      res.json({
        students: results,
        pagination: {
          total,
          page,
          pages: Math.ceil(total / limit),
          hasNext: offset + limit < total,
          hasPrev: page > 1
        }
      });
    });
  });
});

// Get single student
app.get('/api/students/:id', authenticateToken, (req, res) => {
  const query = `
    SELECT s.*, c.course_name, c.course_code 
    FROM students s 
    LEFT JOIN courses c ON s.course_id = c.course_id 
    WHERE s.student_id = ?
  `;

  db.query(query, [req.params.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    res.json(results[0]);
  });
});

// Create new student
app.post('/api/students', authenticateToken, (req, res) => {
  const {
    student_id, first_name, last_name, email, phone, dob,
    address, course_id, admission_date
  } = req.body;

  const query = `
    INSERT INTO students 
    (student_id, first_name, last_name, email, phone, dob, address, course_id, admission_date) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(query, [
    student_id, first_name, last_name, email, phone, dob,
    address, course_id, admission_date
  ], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ error: 'Student ID or email already exists' });
      }
      return res.status(500).json({ error: 'Failed to create student' });
    }
    res.status(201).json({ message: 'Student created successfully', student_id });
  });
});

// Update student
app.put('/api/students/:id', authenticateToken, (req, res) => {
  const {
    first_name, last_name, email, phone, dob,
    address, course_id, status
  } = req.body;

  const query = `
    UPDATE students 
    SET first_name = ?, last_name = ?, email = ?, phone = ?, 
        dob = ?, address = ?, course_id = ?, status = ?
    WHERE student_id = ?
  `;

  db.query(query, [
    first_name, last_name, email, phone, dob,
    address, course_id, status, req.params.id
  ], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to update student' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    res.json({ message: 'Student updated successfully' });
  });
});

// Delete student
app.delete('/api/students/:id', authenticateToken, (req, res) => {
  const query = 'DELETE FROM students WHERE student_id = ?';

  db.query(query, [req.params.id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete student' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    res.json({ message: 'Student deleted successfully' });
  });
});

// ============ COURSE ROUTES ============

// Get all courses
app.get('/api/courses', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM courses ORDER BY course_name';

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch courses' });
    }
    res.json(results);
  });
});

// Create course
app.post('/api/courses', authenticateToken, (req, res) => {
  const { course_name, course_code, credits, duration_years, fee_amount } = req.body;

  const query = 'INSERT INTO courses (course_name, course_code, credits, duration_years, fee_amount) VALUES (?, ?, ?, ?, ?)';

  db.query(query, [course_name, course_code, credits, duration_years, fee_amount], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ error: 'Course code already exists' });
      }
      return res.status(500).json({ error: 'Failed to create course' });
    }
    res.status(201).json({ message: 'Course created successfully', course_id: result.insertId });
  });
});

// ============ ATTENDANCE ROUTES ============

// Mark attendance
app.post('/api/attendance', authenticateToken, (req, res) => {
  const { student_id, course_id, date, status } = req.body;

  const query = 'INSERT INTO attendance (student_id, course_id, date, status, marked_by) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE status = ?, marked_by = ?';

  db.query(query, [student_id, course_id, date, status, req.user.userId, status, req.user.userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to mark attendance' });
    }
    res.json({ message: 'Attendance marked successfully' });
  });
});

// Get attendance for student
app.get('/api/attendance/student/:id', authenticateToken, (req, res) => {
  const query = `
    SELECT a.*, c.course_name, c.course_code 
    FROM attendance a 
    JOIN courses c ON a.course_id = c.course_id 
    WHERE a.student_id = ? 
    ORDER BY a.date DESC
  `;

  db.query(query, [req.params.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch attendance' });
    }
    res.json(results);
  });
});

// ============ FEE ROUTES ============

// Get fees for student
app.get('/api/fees/student/:id', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM fees WHERE student_id = ? ORDER BY due_date DESC';

  db.query(query, [req.params.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch fees' });
    }
    res.json(results);
  });
});

// Create fee record
app.post('/api/fees', authenticateToken, (req, res) => {
  const { student_id, amount, fee_type, due_date } = req.body;

  const query = 'INSERT INTO fees (student_id, amount, fee_type, due_date) VALUES (?, ?, ?, ?)';

  db.query(query, [student_id, amount, fee_type, due_date], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to create fee record' });
    }
    res.status(201).json({ message: 'Fee record created successfully', fee_id: result.insertId });
  });
});

// Update fee payment
app.put('/api/fees/:id/pay', authenticateToken, (req, res) => {
  const { transaction_id, payment_method } = req.body;

  const query = 'UPDATE fees SET status = "paid", paid_date = CURRENT_DATE, transaction_id = ?, payment_method = ? WHERE fee_id = ?';

  db.query(query, [transaction_id, payment_method, req.params.id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to update payment' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Fee record not found' });
    }
    res.json({ message: 'Payment recorded successfully' });
  });
});

// ============ HOSTEL ROUTES ============

// Get hostel allocation for student
app.get('/api/hostel/student/:id', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM hostel WHERE student_id = ?';

  db.query(query, [req.params.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch hostel info' });
    }
    res.json(results[0] || {});
  });
});

// Allocate hostel room
app.post('/api/hostel', authenticateToken, (req, res) => {
  const { student_id, room_number, block, bed_number, monthly_fee } = req.body;

  const query = 'INSERT INTO hostel (student_id, room_number, block, bed_number, allocated_date, monthly_fee) VALUES (?, ?, ?, ?, CURRENT_DATE, ?)';

  db.query(query, [student_id, room_number, block, bed_number, monthly_fee], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to allocate hostel room' });
    }
    res.status(201).json({ message: 'Hostel room allocated successfully' });
  });
});

// ============ NOTIFICATION ROUTES ============

// Get all notifications
app.get('/api/notifications', authenticateToken, (req, res) => {
  const query = `
    SELECT n.*, u.username as created_by_name 
    FROM notifications n 
    LEFT JOIN users u ON n.created_by = u.user_id 
    ORDER BY n.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch notifications' });
    }
    res.json(results);
  });
});

// Create notification
app.post('/api/notifications', authenticateToken, (req, res) => {
  const { title, message, target_audience, is_urgent } = req.body;

  const query = 'INSERT INTO notifications (title, message, target_audience, is_urgent, created_by) VALUES (?, ?, ?, ?, ?)';

  db.query(query, [title, message, target_audience, is_urgent, req.user.userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to create notification' });
    }
    res.status(201).json({ message: 'Notification created successfully', notification_id: result.insertId });
  });
});

// ============ DASHBOARD/ANALYTICS ROUTES ============

// Get dashboard statistics
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
  const queries = {
    totalStudents: 'SELECT COUNT(*) as count FROM students WHERE status = "active"',
    totalCourses: 'SELECT COUNT(*) as count FROM courses',
    pendingFees: 'SELECT COUNT(*) as count FROM fees WHERE status = "pending"',
    totalRevenue: 'SELECT SUM(amount) as total FROM fees WHERE status = "paid"'
  };

  const results = {};
  let completed = 0;

  Object.keys(queries).forEach(key => {
    db.query(queries[key], (err, result) => {
      if (!err) {
        results[key] = result[0];
      }
      completed++;
      if (completed === Object.keys(queries).length) {
        res.json(results);
      }
    });
  });
});

// ============ CONTACT FORM ROUTE ============

// Handle contact form submission
app.post('/api/contact', (req, res) => {
  const { name, email, mobile, message } = req.body;
  
  console.log('Contact form submission:', { name, email, mobile, message });
  
  res.json({ message: 'Thank you for your message! We will get back to you soon.' });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: 'Something went wrong!' });
});

// ✅ FIXED: Single server startup
app.listen(PORT, () => {
  console.log(`🚀 ERP Server with Razorpay running on port ${PORT}`);
  console.log(`🌐 Server URL: http://localhost:${PORT}`);
  console.log(`💰 Payment endpoints:`);
  console.log(`   POST /api/payment/create-order`);
  console.log(`   POST /api/payment/verify-payment`);
  console.log(`📚 ERP endpoints available for students, courses, attendance, fees, etc.`);
});

module.exports = app;
