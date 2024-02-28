const db = require('../db');
const bcrypt = require('bcrypt');
const jwtUtils = require('../token/jwtUtils');
const jwt = require("jsonwebtoken");
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const ejs = require('ejs');

function registerUser(req, res) {
  const {
    fullName,
    contactNo,
    userType,
    personalEmail,
    password
  } = req.body;

  const userId = generateUserID();
  const fetchUserName = `SELECT * FROM app.users WHERE personalemail = $1`;
  const insertUserQuery = `INSERT INTO app.users(userid, fullname, contactno, usertype, personalemail, password, verificationtoken, verified) VALUES($1, $2, $3, $4, $5, $6, $7, $8)`;

  db.query(fetchUserName, [personalEmail], (fetchUsernameError, fetchUsernameResult) => {
    if (fetchUsernameError) {
      return res.status(401).json({ message: 'Error Checking User Email' });
    }
    if (fetchUsernameResult.rows.length > 0) {
      return res.status(401).json({ message: 'User Already Exists' });
    }
    bcrypt.hash(password, 10, (error, hashedPassword) => {
      if (error) {
        return res.status(401).json({ message: 'Error During Hashing Password' });
      }
      const verificationToken = jwtUtils.generateToken({ personalEmail: personalEmail });
      db.query(insertUserQuery, [userId, fullName, contactNo, userType, personalEmail, hashedPassword, verificationToken, '0'], (insertUserError, insertUserResult) => {
        if (insertUserError) {
          console.error('Error during user insertion:', insertUserError);
          return res.status(500).json({ message: 'Internal server error' });
        }
        try {
          sendTokenEmail(personalEmail, verificationToken);
          console.log('User registered successfully');
          return res.status(200).json({ 
            status: 200,
            message: 'Registration successful. Check your email for the verification token.' });
        } catch (sendTokenError) {
          console.error('Error sending verification token:', sendTokenError);
          return res.status(500).json({ message: 'Internal server error' });
        }
      });
    });
  });
}



  
function sendTokenEmail(email, token) {


  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      user: "kpohekar19@gmail.com",
      pass: "woptjevenzhqmrpp"
    },
  });

  // Read the email template file
  const templatePath = path.join(__dirname, '../mail-body/email-template.ejs');
  fs.readFile(templatePath, 'utf8', (err, templateData) => {
    if (err) {
      console.error('Error reading email template:', err);
      return;
    }

    // Compile the email template with EJS
    const compiledTemplate = ejs.compile(templateData);

    // Render the template with the token
    const html = compiledTemplate({ token });

    const mailOptions = {
      from: 'kpohekar19@gmail.com',
      to: email,
      subject: 'Registration Token',
      html: html,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
      } else {
        console.log('Email sent:', info.response);
      }

    });
  });
} 


function getUserById(req, res) {
    const userId = req.params.userId;
    const getUserByUserIdQuery = `SELECT * FROM ORP_users WHERE UserId = $1`;
  
    pool.query(getUserByUserIdQuery, [userId], (fetchUserIdError, fetchUserIdResult) => {
      if (fetchUserIdError) {
        return res.status(401).json({ message: 'Error while fetching user' });
      }
      res.json({ getUserById: fetchUserIdResult.rows });
    });
  }
  
function getUsers(req, res) {
    const getUserByUserQuery = `SELECT * FROM app.users`;
  
    db.query(getUserByUserQuery, (fetchUsersError, fetchUsersResult) => {
      if (fetchUsersError) {
        return res.status(401).json({ message: 'Error while fetching users' });
      }
      res.json({ getUsers: fetchUsersResult.rows });
    });
  }
  
  
  function login(req, res) {
    const { Username, Password } = req.body;
  
    // Check if the user exists in the database
    const query = 'SELECT * FROM app.users WHERE personalemail = $1';
    db.query(query, [Username], (error, result) => {
      try {
        if (error) {
          throw new Error('Error during login');
        }
        const user = result.rows[0];
        if (!user) {
          console.error('User does not exist!');
          return res.status(401).json({ message: 'User does not exist!' });
        }
  
        if (user.verified === 0) {
          console.error('User is not verified. Please verify your account.');
          return res.status(401).json({ message: 'User is not verified. Please verify your account.' });
        }
  
        // Compare the provided password with the hashed password in the database
        bcrypt.compare(Password, user.password, (error, isPasswordValid) => {
          try {
            if (error) {
              throw new Error('Error during password comparison');
            }
  
            if (!isPasswordValid) {
              console.error('Invalid credentials');
              return res.status(401).json({ message: 'Invalid credentials' });
            }
  
            // Generate a JWT token
            const token = jwtUtils.generateToken({ Username: user.username });
  
            // Log the success if no error occurred
            res.json({ token });
          } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Internal server error' });
          }
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });
  }


  function user(req, res) {
    const token = req.headers.authorization.split(' ')[1];
  
    try {
      const decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
  
      if (!decodedToken) {
        return res.status(401).json({ message: 'Invalid token' });
      }
  
      const getUserDetailsQuery = `SELECT * FROM ORP_users WHERE UserName = $1`;
      pool.query(getUserDetailsQuery, [decodedToken.userName], (fetchUserError, fetchUsernameResult) => {
        if (fetchUserError) {
          return res.status(401).json({ message: 'Error while fetching user details' });
        }
        if (fetchUsernameResult.rows.length === 0) {
          return res.status(404).json({ message: 'No user Found' });
        }
        res.json({ user: fetchUsernameResult.rows[0] });
      });
    } catch (error) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  }
  

  function editUser(req, res) {
    const userId = req.params.userId;
    const {
      userName,
      contact,
      firstName,
      lastName,
      companyEmail,
      userType,
      location
    } = req.body;
  
    const editUserQuery = `UPDATE ORP_users SET UserName = $1, FirstName = $2, LastName = $3, CompanyEmail = $4, Contact = $5, UserType = $6, Location = $7 WHERE UserId = $8`;
    
    pool.query(editUserQuery, [
      userName,
      firstName,
      lastName,
      companyEmail,
      contact,
      userType,
      location,
      userId,
    ], (updateError, updateResult) => {
      if (updateError) {
        return res.status(401).json({ message: 'Error While Updating User' });
      }
      return res.status(200).json({ message: 'User Updated Successfully' });
    });
  }
  

  function deleteUser(req, res) {
    const userId = req.params.userId;
    const deleteUserQuery = `DELETE FROM ORP_users WHERE UserId = $1`;
  
    pool.query(deleteUserQuery, [userId], (deleteError, deleteResult) => {
      if (deleteError) {
        return res.status(401).json({ message: 'Error While Deleting User' });
      }
      if (deleteResult.rowCount === 0) {
        return res.status(404).json({ message: 'User Not Found' });
      }
      return res.status(200).json({ message: 'User Deleted Successfully' });
    });
  }
  

function generateUserID() {
  const userIdLength = 10;
  let userId = '';

  const characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  for (let i = 0; i < userIdLength; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    userId += characters.charAt(randomIndex);
  }

  return userId;
}
module.exports = { 
  registerUser,
  getUserById,
  getUsers,
  login,
  user,
  editUser,
  deleteUser,
}