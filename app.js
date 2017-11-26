const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const morgan = require('morgan')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
// ===
const config = require('./config')
const User = require('./models/user')

// CONFIG
const port = process.env.PORT || 2222
mongoose.connect(config.database, { useMongoClient: true })
  .then(() => console.log('Database connected successfully.'))
  .catch(err => console.log('Error connecting to database: ' + err.message))

app.use(morgan('dev'))  // Used to log requests to the console
// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({extended: false}))
app.use(bodyParser.json())

// ROUTES
app.get('/', (req, res) => {
  res.json({message: 'Welcome to out API home page'})
})

// Only users authenticated via checkToken middleware can see all users in database
app.get('/users', checkToken, (req, res) => {
  User.find({}, function(err, users) {
    res.json(users);
  });
})

app.post('/authenticate', (req, res) => {
  User.findOne({ username: req.body.username }, (err, user) => {
    if (err) throw err;
    if (!user) return res.json({
      success: false,
      message: 'Authentication failed. User not found.'
    })
    if (user.password !== req.body.password) return res.json({
      success: false,
      message: 'Authentication failed. Wrong password.'
    })
    const payload = {
      username: user.username
    }
    const token = jwt.sign(payload, config.secret, {
      expiresIn: '1d'
    })
    res.json({
      user: user,
      message: 'You deserve a token!',
      token: token
    })
  })

})

// Middleware
function checkToken (req, res, next) {
  // check header or url parameters or post parameters for token
  const token = req.body.token || req.query.token || req.headers['x-access-token']
  if (token) {
    return jwt.verify(token, config.secret, (err, decodedToken) => {
      if (err) return res.json({
        success: false,
        message: 'Failed to authenticate token.'
      })
      req.decodedToken = decodedToken
      return next()
    })
  }
  return res.json({
    success: false,
    message: 'No token provided.'
  })
}

// Creating a sample user
// app.get('/register', (req, res) => {
//   const myUser = new User({
//     username: 'Gus',
//     password: 'password'
//   })
//   myUser.save((err) => {
//     if (err) throw err;
//     res.json({success: true})
//   })
// })

app.listen(port, () => {
  console.log('Server is up and running...');
})