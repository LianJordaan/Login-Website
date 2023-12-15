const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto'); // For generating random tokens
require('dotenv').config();

const app = express();
const port = 21032;

const nodemailer = require('nodemailer');

// Create a transporter using Gmail SMTP
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASSWORD,
    },
});

module.exports = app;
app.set('views', path.join(__dirname, 'views'));

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true
}));

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL database!');

    const createUsersTableQuery = `CREATE TABLE IF NOT EXISTS users (
    id INT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    verified BOOLEAN DEFAULT 0,
    minecraft_uuid  VARCHAR(255),
    verification_token VARCHAR(255),
    PRIMARY KEY (id),
    UNIQUE KEY (email))`;
    db.query(createUsersTableQuery, (err, result) => {
        if (err) throw err;
        console.log('Users table created or already exists');
    });
});

class User {
    constructor({ email, password, verified = false, verificationToken = null }) {
        this.email = email;
        this.password = password;
        this.verified = verified;
        this.verificationToken = verificationToken;
    }

    hashPassword() {
        this.password = bcrypt.hashSync(this.password, 10);
    }

    checkPassword(password) {
        return bcrypt.compareSync(password, this.password);
    }

    static findOne(email, callback) {
        db.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
            if (error) return callback(error);
            if (results.length === 0) return callback(null, null);
            const user = new User(results[0]);
            callback(null, user);
        });
    }

    save(callback) {
        db.query('INSERT INTO users SET ?', { email: this.email, password: this.password, verification_token: this.verificationToken }, (error, result) => {
            if (error) return callback(error);
            this.id = result.insertId;
            callback(null, this);
        });
    }

    // Function to send email with verification link
    sendVerificationEmail() {
        const verificationLink = `${process.env.APP_URL}/verify?token=${this.verificationToken}`;
        const mailOptions = {
            from: process.env.MAIL_USER,
            to: this.email,
            subject: 'Email Verification',
            html: `<p>Click <a href="${verificationLink}">here</a> to verify your email address.</p>`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending email:', error);
            } else {
                console.log('Verification email sent:', info.response);
            }
        });
    }
}

app.get('/', (req, res) => {
    if (req.session.user) {
        res.render('index.ejs', {
            message: '',
            user: req.user
          });
    } else {
      res.redirect('/login');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/login', (req, res) => {
    let errorMessage = '';

    if (req.query.error) {
      errorMessage = 'Invalid email or password. Please try again.';
    }

    res.render('login', { errorMessage: errorMessage });

});

app.get('/register', (req, res) => {
    let errorMessage = '';

    if (req.query.error) {
      errorMessage = 'Invalid email or password. Please try again.';
    }

    res.render('register', { errorMessage: errorMessage });
    
});

app.get('/verification', (req, res) => {
    res.render('verification');
});

app.post('/register', (req, res) => {
    const { email, password } = req.body;
    User.findOne(email, (err, user) => {
        if (err) {
            console.log(err);
            return res.status(500).send('An error occurred');
        }
        if (user) {
            res.render('register.ejs', {
                errorMessage: 'Email already exists!',
                user: req.user
            });
        } else {
            // Generate a random verification token
            const verificationToken = crypto.randomBytes(32).toString('hex');
            const newUser = new User({ email, password, verificationToken });
            newUser.hashPassword();
            newUser.sendVerificationEmail(); // Send verification email
            newUser.save((err, savedUser) => {
                if (err) {
                    console.log(err);
                    return res.status(500).send('An error occurred');
                }
                res.redirect('/verification');
            });
        }
    });
});

app.get('/verify', (req, res) => {
    const { token } = req.query;
    if (!token) {
        return res.status(400).send('Invalid verification token.');
    }

    // Find the user by verification token
    db.query('SELECT * FROM users WHERE verification_token = ?', [token], (error, results) => {
        if (error) {
            console.log(error);
            return res.status(500).send('An error occurred during verification.');
        }
        if (results.length === 0) {
            return res.status(404).send('Verification token not found.');
        }

        // Mark the user as verified and remove the verification_token
        const user = results[0];
        db.query('UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?', [user.id], (updateError, updateResult) => {
            if (updateError) {
                console.log(updateError);
                return res.status(500).send('An error occurred during verification.');
            }
            
            req.session.user = { email: user.email };
            res.redirect('/');
        });
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
  
    User.findOne(email, (err, user) => {
      if (err) {
        console.log(err);
        return res.status(500).send('An error occurred');
      }
      if (!user || !user.checkPassword(password)) {
        return res.status(401).render('login', { errorMessage: 'Invalid email or password' });
      }
      if (!user.verified) {
        return res.status(401).render('login', { errorMessage: 'Email not verified. Please check your email for a verification link.' });
      }
      req.session.user = { email };
      res.redirect('/');
    });
});

// Create the minecraft_verification table
db.query(`
    CREATE TABLE IF NOT EXISTS minecraft_verification (
        id INT AUTO_INCREMENT PRIMARY KEY,
        minecraft_uuid VARCHAR(255) NOT NULL UNIQUE,
        token VARCHAR(255) NOT NULL
    )
`, (err) => {
    if (err) {
        console.error('Error creating the minecraft_verification table:', err);
    } else {
        console.log('Table "minecraft_verification" created successfully');
    }
});

// Insert username:token pair into the minecraft_verification table
app.use('/receive-token', bodyParser.urlencoded({ extended: true }));
app.use('/receive-token', bodyParser.json());

// Handle the /receive-token POST request
app.post('/receive-token', (req, res) => {
    const { minecraftUsername, token } = req.body;

    if (!minecraftUsername || !token) {
        // Check if both minecraftUsername and token are present in the request body
        return res.status(400).json({ message: 'minecraftUsername and token are required' });
    }

    // Insert or update the pair into the minecraft_verification table
    db.query('INSERT INTO minecraft_verification (minecraft_uuid, token) VALUES (?, ?) ON DUPLICATE KEY UPDATE token = ?', [minecraftUsername, token, token], (err) => {
        if (err) {
            console.error('Error inserting or updating username:token pair:', err);
            res.status(400).json({ message: 'Failed to insert or update username:token pair' });
        } else {
            res.status(200).json({ message: 'Username:token pair received and stored or updated' });
        }
    });
});


// GET endpoint to display the page for linking Minecraft accounts
app.get('/settings', (req, res) => {
    // Check if there is a user session
    if (req.session.user) {
        // Render the page where authenticated users can link their Minecraft UUID
        res.render('settings.ejs', { errorMessage: null, user: req.user }); // Replace 'link-account.ejs' with the actual template
    } else {
        // If not authenticated, redirect to the login page or show an error
        res.redirect('/login'); // Replace with your login route
    }
});

app.use('/link-account', bodyParser.urlencoded({ extended: true }));
app.use('/link-account', bodyParser.json());
// POST endpoint to link a Minecraft account
app.post('/link-account', async (req, res) => {
    const { minecraftUUID, token } = req.body;

    try {
        // Check if there's a matching UUID:token pair in the minecraft_verification table
        const verificationResults = await new Promise((resolve, reject) => {
            db.query('SELECT * FROM minecraft_verification WHERE minecraft_uuid = ? AND token = ?', [minecraftUUID, token], (err, results) => {
                if (err) {
                    console.error('Error checking UUID:token pair:', err);
                    reject(err);
                } else {
                    resolve(results);
                }
            });
        });

        if (verificationResults.length === 0) {
            // No matching pair found
            return res.status(400).json({ message: 'Invalid UUID:token pair' });
        }

        // Matching pair found, remove it from the minecraft_verification table
        await new Promise((resolve, reject) => {
            db.query('DELETE FROM minecraft_verification WHERE minecraft_uuid = ? AND token = ?', [minecraftUUID, token], (err) => {
                if (err) {
                    console.error('Error deleting UUID:token pair:', err);
                    reject(err);
                } else {
                    console.log('UUID:token pair deleted successfully');
                    resolve();
                }
            });
        });

        // Update the user's 'users' table record with their Minecraft UUID
        const user = req.session.user;

        // Check if the user is authenticated
        if (!user) {
            // Handle the case where the user is not authenticated
            return res.status(401).json({ message: 'User is not authenticated' });
        }

        // Access the email property from the User object
        const userEmail = user.email;

        await new Promise((resolve, reject) => {
            db.query('UPDATE users SET minecraft_uuid = ? WHERE email = ?', [minecraftUUID, userEmail], (err, result) => {
                if (err) {
                    console.error('Error updating Minecraft UUID:', err);
                    reject(err);
                } else {
                    if (result.affectedRows === 1) {
                        console.log('Minecraft UUID updated successfully');
                        resolve();
                    } else {
                        console.log('No user found or no update needed');
                        reject(new Error('User not found or no update needed'));
                    }
                }
            });
        });

        return res.status(200).json({ message: 'Minecraft account linked successfully' });
    } catch (error) {
        console.error('Error:', error);
        // Render the 'link-account.ejs' page with an error message
        res.render('link-account.ejs', { errorMessage: 'An error occurred', user: req.session.user });
    }
});

app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);
});
