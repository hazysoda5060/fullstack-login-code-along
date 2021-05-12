require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');
const authCtrl = require('../controllers/authController')

const app = express();

app.use(express.json());

let {SERVER_PORT, CONNECTION_STRING, SESSION_SECRET} = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive({
  connectionString: CONNECTION_STRING,
  ssl: {rejectUnauthorized: false}
}).then(db => {
  app.set('db', db);
});

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT} :3`);
});


app.post('/auth/signup', authCtrl.register)
app.post('/auth/login', authCtrl.login)
app.get('/auth/logout', authCtrl.logout)