require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./config/db');

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-fallback-secret-key';

// Authentication Middleware
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

// Auth Routes
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, phone, dob, gender, address } = req.body;

        // Validate input
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email and password are required' });
        }

        // Check if email exists
        const [existing] = await db.query('SELECT id FROM students WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Prepare values (handle optional empty fields)
        const studentValues = [
            name,
            email,
            hashedPassword,
            phone || null,
            dob || null,
            gender || null,
            address || null
        ];

        // Insert student
        const [result] = await db.query(
            'INSERT INTO students (name, email, password, phone, dob, gender, address) VALUES (?, ?, ?, ?, ?, ?, ?)',
            studentValues
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
        console.log(`Login attempt for: ${email}`);

        // Validate input
        if (!email || !password) {
            console.log('Login failed: Missing required fields');
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Get student
        const [students] = await db.query('SELECT * FROM students WHERE email = ?', [email]);
        if (students.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const student = students[0];

        // Check password
        const validPassword = await bcrypt.compare(password, student.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate token
        const token = jwt.sign(
            { id: student.id, email: student.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: student.id,
                name: student.name,
                email: student.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Protected Routes
app.use('/api/students', authenticateToken);
app.use('/api/courses', authenticateToken);
app.use('/api/enrollments', authenticateToken);
app.use('/api/attendance', authenticateToken);
app.use('/api/grades', authenticateToken);

// Students
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

app.post('/api/students', async (req, res) => {
    try {
        const { name, email, password, phone, dob, gender, address } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email and password are required' });
        }

        // Check if email exists
        const [existing] = await db.query('SELECT id FROM students WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await db.query(
            'INSERT INTO students (name, email, password, phone, dob, gender, address) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, phone, dob, gender, address]
        );

        res.json({
            message: 'Student added successfully',
            id: result.insertId,
            name,
            email
        });
    } catch (error) {
        console.error('Error adding student:', error);
        res.status(500).json({ error: 'Database error while adding student' });
    }
});

app.put('/api/students/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, email, phone, dob, gender, address } = req.body;
        await db.query(
            'UPDATE students SET name = ?, email = ?, phone = ?, dob = ?, gender = ?, address = ? WHERE id = ?',
            [name, email, phone, dob, gender, address, id]
        );
        res.json({ message: 'Student updated successfully' });
    } catch (error) {
        console.error('Error updating student:', error);
        res.status(500).json({ error: 'Database error while updating student' });
    }
});

app.delete('/api/students/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await db.query('DELETE FROM students WHERE id = ?', [id]);
        res.json({ message: 'Student deleted successfully' });
    } catch (error) {
        console.error('Error deleting student:', error);
        res.status(500).json({ error: 'Database error while deleting student' });
    }
});

// Courses
app.get('/api/courses', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT c.*,
                   COUNT(DISTINCT e.student_id) as enrolled_students,
                   AVG(g.score) as average_grade
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

app.post('/api/courses', async (req, res) => {
    try {
        const { name, code, instructor, credits } = req.body;

        if (!name || !code || !instructor || !credits) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if course code exists
        const [existing] = await db.query('SELECT id FROM courses WHERE code = ?', [code]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Course code already exists' });
        }

        const [result] = await db.query(
            'INSERT INTO courses (name, code, instructor, credits) VALUES (?, ?, ?, ?)',
            [name, code, instructor, credits]
        );

        res.json({
            message: 'Course added successfully',
            id: result.insertId,
            name,
            code
        });
    } catch (error) {
        console.error('Error adding course:', error);
        res.status(500).json({ error: 'Database error while adding course' });
    }
});

app.put('/api/courses/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, code, instructor, credits } = req.body;
        await db.query(
            'UPDATE courses SET name = ?, code = ?, instructor = ?, credits = ? WHERE id = ?',
            [name, code, instructor, credits, id]
        );
        res.json({ message: 'Course updated successfully' });
    } catch (error) {
        console.error('Error updating course:', error);
        res.status(500).json({ error: 'Database error while updating course' });
    }
});

app.delete('/api/courses/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await db.query('DELETE FROM courses WHERE id = ?', [id]);
        res.json({ message: 'Course deleted successfully' });
    } catch (error) {
        console.error('Error deleting course:', error);
        res.status(500).json({ error: 'Database error while deleting course' });
    }
});

// Enrollments
app.get('/api/enrollments', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT e.*,
                   s.name as student_name,
                   c.name as course_name,
                   c.code as course_code,
                   AVG(g.score) as current_grade
            FROM enrollments e
            JOIN students s ON e.student_id = s.id
            JOIN courses c ON e.course_id = c.id
            LEFT JOIN grades g ON e.student_id = g.student_id AND e.course_id = g.course_id
            GROUP BY e.id
            ORDER BY e.enrollment_date DESC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching enrollments:', error);
        res.status(500).json({ error: 'Database error while fetching enrollments' });
    }
});

app.post('/api/enrollments', async (req, res) => {
    try {
        const { student_id, course_id } = req.body;

        if (!student_id || !course_id) {
            return res.status(400).json({ error: 'Student ID and Course ID are required' });
        }

        // Check if student exists
        const [student] = await db.query('SELECT id FROM students WHERE id = ?', [student_id]);
        if (student.length === 0) {
            return res.status(404).json({ error: 'Student not found' });
        }

        // Check if course exists
        const [course] = await db.query('SELECT id FROM courses WHERE id = ?', [course_id]);
        if (course.length === 0) {
            return res.status(404).json({ error: 'Course not found' });
        }

        // Check if already enrolled
        const [existing] = await db.query(
            'SELECT id FROM enrollments WHERE student_id = ? AND course_id = ?',
            [student_id, course_id]
        );
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Student is already enrolled in this course' });
        }

        const [result] = await db.query(
            'INSERT INTO enrollments (student_id, course_id, enrollment_date) VALUES (?, ?, CURDATE())',
            [student_id, course_id]
        );

        res.json({
            message: 'Enrollment successful',
            id: result.insertId
        });
    } catch (error) {
        console.error('Error adding enrollment:', error);
        res.status(500).json({ error: 'Database error while adding enrollment' });
    }
});

// Attendance
app.get('/api/attendance', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT a.*,
                   s.name as student_name,
                   c.name as course_name,
                   c.code as course_code
            FROM attendance a
            JOIN students s ON a.student_id = s.id
            JOIN courses c ON a.course_id = c.id
            ORDER BY a.date DESC, a.created_at DESC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching attendance:', error);
        res.status(500).json({ error: 'Database error while fetching attendance' });
    }
});

app.post('/api/attendance', async (req, res) => {
    try {
        const { student_id, course_id, date, status } = req.body;

        if (!student_id || !course_id || !date || !status) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Validate status
        if (!['present', 'absent', 'late'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status value' });
        }

        // Check if attendance already marked
        const [existing] = await db.query(
            'SELECT id FROM attendance WHERE student_id = ? AND course_id = ? AND date = ?',
            [student_id, course_id, date]
        );
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Attendance already marked for this date' });
        }

        const [result] = await db.query(
            'INSERT INTO attendance (student_id, course_id, date, status) VALUES (?, ?, ?, ?)',
            [student_id, course_id, date, status]
        );

        res.json({
            message: 'Attendance marked successfully',
            id: result.insertId
        });
    } catch (error) {
        console.error('Error marking attendance:', error);
        res.status(500).json({ error: 'Database error while marking attendance' });
    }
});

// Grades
app.get('/api/grades', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT g.*,
                   s.name as student_name,
                   c.name as course_name,
                   c.code as course_code
            FROM grades g
            JOIN students s ON g.student_id = s.id
            JOIN courses c ON g.course_id = c.id
            ORDER BY g.date DESC, g.created_at DESC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching grades:', error);
        res.status(500).json({ error: 'Database error while fetching grades' });
    }
});

app.post('/api/grades', async (req, res) => {
    try {
        const { student_id, course_id, assessment_name, score } = req.body;

        if (!student_id || !course_id || !assessment_name || score === undefined) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Validate score
        if (score < 0 || score > 100) {
            return res.status(400).json({ error: 'Score must be between 0 and 100' });
        }

        // Calculate grade
        let grade;
        if (score >= 90) grade = 'A';
        else if (score >= 80) grade = 'B';
        else if (score >= 70) grade = 'C';
        else if (score >= 60) grade = 'D';
        else grade = 'F';

        const [result] = await db.query(
            'INSERT INTO grades (student_id, course_id, assessment_name, score, grade, date) VALUES (?, ?, ?, ?, ?, CURDATE())',
            [student_id, course_id, assessment_name, score, grade]
        );

        // Calculate and update average grade
        const [avgGrade] = await db.query(`
            SELECT AVG(score) as average_grade
            FROM grades
            WHERE student_id = ? AND course_id = ?
        `, [student_id, course_id]);

        res.json({
            message: 'Grade added successfully',
            id: result.insertId,
            grade,
            average_grade: avgGrade[0].average_grade
        });
    } catch (error) {
        console.error('Error adding grade:', error);
        res.status(500).json({ error: 'Database error while adding grade' });
    }
});

// Error Handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
}); 