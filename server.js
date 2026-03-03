require('dotenv').config();
const mysql = require('mysql2/promise');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// 1. DATABASE CONNECTION (Defined directly here to avoid missing folder errors)
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 19638,
    ssl: {
        rejectUnauthorized: false
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const app = express();

// 2. MIDDLEWARE
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// 3. JWT SECRET
const JWT_SECRET = process.env.JWT_SECRET || 'your-fallback-secret-key';

// 4. AUTHENTICATION MIDDLEWARE
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// 5. AUTH ROUTES
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, phone, dob, gender, address } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email and password are required' });
        }
        const [existing] = await db.query('SELECT id FROM students WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query(
            'INSERT INTO students (name, email, password, phone, dob, gender, address) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, phone || null, dob || null, gender || null, address || null]
        );
        res.json({ message: 'Registration successful', id: result.insertId });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        const [students] = await db.query('SELECT * FROM students WHERE email = ?', [email]);
        if (students.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const student = students[0];
        const validPassword = await bcrypt.compare(password, student.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: student.id, email: student.email }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: student.id, name: student.name, email: student.email } });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// 6. PROTECTED ROUTES
app.use('/api/students', authenticateToken);
app.use('/api/courses', authenticateToken);
app.use('/api/enrollments', authenticateToken);
app.use('/api/attendance', authenticateToken);
app.use('/api/grades', authenticateToken);

// --- Students API ---
app.get('/api/students', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT s.id, s.name, s.email, s.phone, s.dob, s.gender, s.address,
                   COUNT(DISTINCT e.course_id) as enrolled_courses,
                   AVG(g.score) as average_grade
            FROM students s
            LEFT JOIN enrollments e ON s.id = e.student_id
            LEFT JOIN grades g ON s.id = g.student_id
            GROUP BY s.id
            ORDER BY s.created_at DESC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching students:', error);
        res.status(500).json({ error: 'Database error while fetching students' });
    }
});

// --- Courses API ---
app.get('/api/courses', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT c.*, COUNT(DISTINCT e.student_id) as enrolled_students, AVG(g.score) as average_grade
            FROM courses c
            LEFT JOIN enrollments e ON c.id = e.course_id
            LEFT JOIN grades g ON c.id = g.course_id
            GROUP BY c.id
            ORDER BY c.created_at DESC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching courses:', error);
        res.status(500).json({ error: 'Database error while fetching courses' });
    }
});

// 7. ERROR HANDLER
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// 8. START SERVER
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
