const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const port = 3000;



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
    host: process.env.HOST,
    user: process.env.USER,
    password: process.env.PASSWORD,
    database: process.env.DATABASE
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL database!');

    const createUsersTableQuery = `CREATE TABLE IF NOT EXISTS users (
        id INT NOT NULL AUTO_INCREMENT,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY (email)
    )`;
    db.query(createUsersTableQuery, (err, result) => {
        if (err) throw err;
        console.log('Users table created or already exists');
    });
});

class User {
    constructor({ email, password }) {
        this.email = email;
        this.password = password;
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
        db.query('INSERT INTO users SET ?', { email: this.email, password: this.password }, (error, result) => {
            if (error) return callback(error);
            this.id = result.insertId;
            callback(null, this);
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
            const newUser = new User({ email, password });
            newUser.hashPassword();
            newUser.save((err, savedUser) => {
                if (err) {
                    console.log(err);
                    return res.status(500).send('An error occurred');
                }
                res.redirect('/');
            });
        }
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
      req.session.user = { email };
      res.redirect('/');
    });
});

app.post('/editfile', (req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      const { file_name, data_dir, content, password } = JSON.parse(body);
      if (password !== 'site') {
        res.status(401).send('Unauthorized');
        return;
      }
      const filePath = path.join(__dirname, data_dir, file_name);
      fs.writeFile(filePath, content, (err) => {
        if (err) {
          res.status(500).send(`Error saving file: ${err}`);
          return;
        }
        res.status(200).send(`Successfully saved file: ${file_name}`);
      });
    });
  });