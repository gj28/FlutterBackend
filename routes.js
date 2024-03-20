const express = require('express');
const router = express.Router();
const authentication = require('./auth/authentication');
const dashboard = require('./dash/dashboard.js');
const limitter = require('express-rate-limit');

// const registerLimitter = limitter({
//     windowMS : 5*60*1000,
//     max: 2,
// })

// const loginLimit = limitter({
//     windowMS : 1*60*1000,
//     max: 5,
// })
  
// Authentication post/put route

router.post('/addUser', authentication.registerUser);
router.get('/fetchUserById/:userId',authentication.getUserById);
router.get('/fetchAllUsers',authentication.getUsers);
router.post('/login', authentication.login);
router.get('/user', authentication.user);
router.put('/editUser/:userId', authentication.editUser);
router.delete('/deleteUser/:userId', authentication.deleteUser);

//forget pass
router.post('/forgot', authentication.forgotPassword);
router.post('/reset-password', authentication.resetPassword);

// dash

router.put('/updatePassword/:UserId', authentication.updatePassword);


module.exports = router;
