'use strict'

/**
 * Dependencies
 * @ignore
 */
const path = require('path')
const express = require('express')
const bodyParser = require('body-parser')
const session = require('express-session')
const Webauthn = require('webauthn')

/**
 * Module Dependencies
 * @ignore
 */
const LevelAdapter = require('webauthn/src/LevelAdapter')

/**
 * Example
 * @ignore
 */
const app = express()

// Session
app.use(session({
  secret: 'keyboard cat',
  saveUninitialized: true,
  resave: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}))

// Static
app.use(express.static(path.join(__dirname, 'build')))

// Body parsing
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

// Create webauthn
const webauthn = new Webauthn({
  origin: 'https://eosinabox.amiheines.com',
  rpId: 'https://eosinabox.amiheines.com',
  rpName: 'AmiHeines.com EOS-in-a-Box',
  authenticatorSelection: {authenticatorAttachment: "platform"},
  attestation: "direct",
  pubKeyCredParams: [{alg: -7, type: "public-key"}],
  usernameField: 'username',
  userFields: {
    username: 'username',
    name: 'displayName',
  },
  store: new LevelAdapter('db'),
  // OR
  // store: {
  //   put: async (id, value) => {/* return <void> */},
  //   get: async (id) => {/* return User */},
  //   search: async (search) => {/* return { [username]: User } */},
  //   delete: async (id) => {/* return boolean */},
  // },
})

// Mount webauthn endpoints
app.use('/webauthn', webauthn.initialize())

// Endpoint without passport
app.get('/authenticators', webauthn.authenticate(), async (req, res) => {
  var userr = await webauthn.store.get(req.session.username)
  console.log('AMIHDEBUG authenticators... userr:', userr);
  res.status(200).json([ userr ].map(user => user.authenticator))
})

// Debug
app.get('/db', async (req, res) => {
  res.status(200).json(await webauthn.store.search())
})

// Debug
app.get('/session', (req, res) => {
  res.status(200).json(req.session)
})

// Serve React App
app.use((req, res) => {
  return res.sendFile(path.join(__dirname, 'build', 'index.html'))
})

// Listen
const port = process.env.PORT || 3000
app.listen(port, () => {
  console.log('Listening on port', port)
})
