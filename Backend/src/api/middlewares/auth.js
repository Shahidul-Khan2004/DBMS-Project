// import bcrypt from 'bcrypt';
// import { query } from '../../config/db.js';

// export async function registerUser(req, res) {
//   try {
//     const { email, fullName, password} = req.body;

//     const userExists = await query('SELECT id FROM users WHERE email = $1', [email]);
//     if (userExists.rows.length > 0) {
//       return res.status(409).json({ error: 'Email already in use' });
//     }

//     const saltRounds = 10;
//     const passwordHash = await bcrypt.hash(password, saltRounds);

//     const insertQuery = `
//       INSERT INTO users (email, full_name, password_hash) 
//       VALUES ($1, $2, $3) 
//       RETURNING id, email, full_name, created_at;
//     `;
//     const result = await query(insertQuery, [email, fullName, passwordHash]);

//     res.status(201).json({
//       message: 'User registered successfully',
//       user: result.rows[0],
//     });
//   } catch (error) {
//     console.error('Registration Error:', error);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// }