const express = require('express');
const router = require('./routes');
const limitter = require('express-rate-limit');
const fs = require('fs');
const bodyParser = require('body-parser');
const app = express();
const port = 3000;

app.use(express.json());
app.use(bodyParser.json());

// Use the router for handling routes
app.use(router);

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
