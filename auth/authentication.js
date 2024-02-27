const db = require('../db');
const bcrypt = require('bcrypt');
//const jwtUtils = require('../token/jwtUtils');
const jwt = require("jsonwebtoken");

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
    const insertUserQuery = `INSERT INTO app.users(userid, fullname, contactno, usertype, personalemail, password) VALUES($1, $2, $3, $4, $5, $6)`;
    
    db.query(fetchUserName, [personalEmail], (fetchUsernameError, fetchUsernameResult) => {
        //console.log(fetchUsernameError);
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
        db.query(insertUserQuery, [userId, fullName, contactNo, userType, personalEmail, hashedPassword], (insertUserError, insertUserResult) => {
          if (insertUserError) {
            //console.log(insertUserError);
            return res.status(401).json({ message: 'Error during Inserting User' });
          }
          return res.status(200).json({ message: 'User Added Successfully' });
        });
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
    const getUserByUserQuery = `SELECT * FROM ORP_users`;
  
    pool.query(getUserByUserQuery, (fetchUsersError, fetchUsersResult) => {
      if (fetchUsersError) {
        return res.status(401).json({ message: 'Error while fetching users' });
      }
      res.json({ getUsers: fetchUsersResult.rows });
    });
  }
  
  function login(req, res) {
    const { userName, password } = req.body;
    const checkUserNameQuery = `SELECT * FROM ORP_users WHERE UserName = $1`;
  
    pool.query(checkUserNameQuery, [userName], (checkUserNameError, checkUserNameResult) => {
      if (checkUserNameError) {
        return res.status(401).json({ message: 'Error While Checking UserName' });
      }
      if (checkUserNameResult.rows.length === 0) {
        return res.status(401).json({ message: 'Username Not Found' });
      }
  
      const user = checkUserNameResult.rows[0];
      bcrypt.compare(password, user.password, (passwordCheckError, passwordCheckResult) => {
        if (passwordCheckError) {
          console.log(passwordCheckError);
          return res.status(401).json({ message: 'Error During Password Comparison' });
        }
        if (!passwordCheckResult) {
          return res.status(401).json({ message: 'Invalid Credentials' });
        }
        const jwToken = jwt.sign({ userName: user.UserName }, process.env.JWT_SECRET_KEY);
        return res.status(200).json({
          message: 'Login Successful',
          token: jwToken,
        });
      });
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