# AmiH

https://webauthn.guide/

https://github.com/EOSIO/eosio-webauthn-example-app

https://github.com/EOSIO/eosio-webauthn-example-app/blob/master/src/server/server.ts

https://github.com/amih/webauthnStrangeLabs/commits/master


I need to take the essense of the webauthn example of B1 and incorporate it into the webauthn example of the webauthn npm package that is running on eosinabox.amiheines.com
I will then find the webauthn pubkey, use that to create a EosioSignatureRequest, let the user SHARE it with the friend which will use Anchor wallet to create the account for the user.
Need to let the user choose who is the trusted account or pubkey, in the future - let the trusted friend send him a more advanced threshold based owner.
Allow the user to check if the account name is valid, give hints with local messages, a-z1-5 12 characters.
Once the user enters a legal account, make the "check if available" button on.
Support EOS and Jungle3.
Change background when using Jungle3
If account name is available, create the ESR and allow to SHARE.

Refresh, check if account is created
Allow user to send EOS from the account
Allow user to send other tokens from the account
How to watch balance of _any_ token on the EOS net?
Keep all info in localstorage?

# Main flows in the app

1. Completely new? Create an account!
    * I will pre-populate the blockchain to be EOS
    * Please choose a 12 character name for your account, characters can be letters in range: a-z or digits in range 1-5, I (the app) will check validity and availability of the account
    * Choose who to trust with managing your account, enter their account here, I (the app) will check this account exists
    * Create the keys with your phone’s security, either fingerprint or face id
    * Almost done, here is the account creation info, send this to the trusted friend and they will create the account for you.
2. Want to help a friend create an account?
    * What blockchain? EOS - the main net or Jungle3 - the test net? Soon we will support additional EOSIO compatible blockchains
    * Talk to them about choosing a legal and available account name
    * Who will be the trusted account in case they need to regain access to their account from another phone? The owner permission.
    * Send them this link which will pre-populate the info, they will need to create a key pair using their phone and, this will make it easier for them to create an account request which they will send back to you to sign.
    * You will be paying a little EOS to buy the RAM for the account creation.
3. Regain access to an account
    * Choose the blockchain, I will pre-populate EOS for you as the default but you can change this
    * Enter the account you own and want to regain access to
    * Create new keys with your phone’s security
    * Almost done, here is the change key request, send it to the trusted friend and they will send the request to the blockchain.
4. Send tokens from your wallet to another account
    * How much and what token?
    * Who to send to?
    * Want to add a short memo message?
    * Approve with your phone’s security
    * All done!
5. Approve any transaction request
    * Copy-paste the ESR (EOSIO-Signing-Request) here
    * Approve with your phone’s security
    * All done!
6. Delete account keys from this phone
    * Choose which account keys to delete, or choose “All”
    * Are you sure? This can’t be undone, you will need the assistance of the owner permission to regain access to the account keys you delete.


# WebAuthn

[![standard-readme compliant](https://img.shields.io/badge/standard--readme-OK-green.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)
[![build-status](https://travis-ci.com/strangerlabs/webauthn.svg?branch=master)](https://travis-ci.com/strangerlabs/webauthn)
[![codecov](https://codecov.io/gh/strangerlabs/webauthn/branch/master/graph/badge.svg)](https://codecov.io/gh/strangerlabs/webauthn)

> W3C Web Authentication API Relying Party for Node.js and Express

WebAuthn is a [W3C standard][w3c] that enables web developers to replace passwords in their applications with [FIDO authentication][fido2]. This repository implements a NPM package for use in Node.js services. **This package is in active development and not yet ready for production use. You can use it to kick the tires on WebAuthn. Please file issues to ask questions or provide feedback.**

[w3c]: https://w3c.github.io/webauthn/
[fido2]: https://fidoalliance.org/fido2/

## Table of Contents

- [WebAuthn](#webauthn)
  - [Table of Contents](#table-of-contents)
  - [Security](#security)
  - [Install](#install)
  - [Usage](#usage)
  - [API](#api)
    - [Relying Party](#relying-party)
    - [Storage Adapater](#storage-adapater)
    - [Browser Client](#browser-client)
  - [Maintainers](#maintainers)
  - [Contributing](#contributing)
    - [Issues](#issues)
    - [Pull requests](#pull-requests)
      - [Policy](#policy)
      - [Style guide](#style-guide)
      - [Code reviews](#code-reviews)
    - [Tests](#tests)
    - [Code of conduct](#code-of-conduct)
  - [License](#license)

## Security

This package is not yet ready for use in production software. For more information on security considerations see [W3C Web Authentication][w3c-sec] and [FIDO Security Reference][fido-sec].

[w3c-sec]: https://w3c.github.io/webauthn/#security-considerations
[fido-sec]: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-security-ref-v2.0-rd-20180702.html

## Install

```sh
$ npm install webauthn
```

## Usage

See [examples](./example) for a complete example. The package currently works on its own and we plan to support Passport.js integration in future releases.

```javascript
const WebAuthn = require('webauthn')

// configure express and session middleware; see "examples" in this repository
// ...

// Create webauthn
const webauthn = new WebAuthn({
  origin: 'http://localhost:3000',
  usernameField: 'username',
  userFields: {
    username: 'username',
    name: 'displayName',
  },
  store: new LevelAdapter(),
  // OR
  // store: {
  //   put: async (id, value) => {/* return <void> */},
  //   get: async (id) => {/* return User */},
  //   search: async (search) => {/* return { [username]: User } */},
  //   delete: async (id) => {/* return boolean */},
  // },
  rpName: 'Stranger Labs, Inc.',
  enableLogging: false,
})

// Mount webauthn endpoints
app.use('/webauthn', webauthn.initialize())

// Endpoint without passport
app.get('/secret', webauthn.authenticate(), (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Super Secret!' })
})
```

Client

```javascript
import Client from 'webauthn/client'

const client = new Client({ pathPrefix: '/webauthn' })

await client.register({
  username: 'AL1C3',
  name: 'Alice',
})

// ...

await client.login({ username: 'AL1C3' })
```

## API

[cred-mgmt-api]: https://developer.mozilla.org/en-US/docs/Web/API/Credential_Management_API
[express-js-router]: https://expressjs.com/en/api.html#express.router
[express-js-middleware]: https://expressjs.com/en/guide/using-middleware.html

### Relying Party

**`new WebAuthn(options)`**

The main entrypoint for creating a new WebAuthn RP instance. `options` is used
to configure the behaviour of the RP. Available options include:

- `origin` - The origin of the deployed application.
- `rpName` - The display name of RP. This will be shown in the WebAuthn consent
interface.
- `[usernameField = 'name']` - The name of the field that uniquely identifies a
user.
- `[userFields = ['name', 'displayName'] ]` - One of:
  - An array of properties from registration request to be included in the saved
  user object
  - An object mapping, where the key is the name of a property from the
  registration request to be included in the user object and the value is the
  name of that property on the user object.
- `[store = MemoryAdapter]` - The storage interface for user objects. Defaults
to an object in memory (for testing only).
- `[attestation = 'none']` - the [attestation conveyance preference](
https://w3c.github.io/webauthn/#enum-attestation-convey). Setting this to
anything other than `'none'` will require attestation and validate it.
- `[credentialEndpoint = '/register']` - the path of the credential attestation
challenge endpoint.
- `[assertionEndpoint = '/login']` - the path of the challenge assertion
endpoint.
- `[challengeEndpoint = '/response']` - the path of the challenge response
endpoint.
- `[logoutEndpoint = '/logout']` - the path of the logout endpoint.
- `[enableLogging = true]` - Enable or disable logging to stdout.

**`webauthn.initialize()`**

Returns an [Express Router][express-js-router] with the mounted WebAuthn
endpoints.

**`webauthn.authenticate([options])`**

Returns an [Express Middleware][express-js-middleware] that will set `req.user`
for subsequent middlewares, or produce a `401 Unauthorized` error if the user is
not authenticated. Available options include:

- `[failureRedirect]` - If the user fails to authenticate then they will be
redirected to the supplied URL.

### Storage Adapater

Storage adapters provide an interface to the WebAuthn RP to store and retrieve
data necessary for authentication, such as authenticator public keys. Storage
adapters must implement the following interface:

**`async get (id)`**

Retrieves and returns the previously stored object with the provided `id`.

**`async put (id, value)`**

Stores an object so that it may be retrieved with the provided `id`. Returns
nothing.

**`async search (startsWith, [options])`**

Returns a mapping of objects where the `id` of the objects return starts with
the provided query value. Available options include:

- `limit`: Return the first N results.
- `reverse`: Return results in reverse lexicographical order. If used in
conjunction with limit then the _last_ N results are returned.

**`async delete (id)`**

Delete a previously stored object. Returns a boolean indicating success.

### Browser Client

**`new Client([options])`**

Constructs a new client for handling interaction with the Web Authentication API
and the server authentication endpoints. Available options include:

- `[pathPrefix = '/webauthn']` - A mounting prefix to all authorization
endpoints.
- `[credentialEndpoint = '/register']` - The path of the credential registration
endpoint.
- `[assertionEndpoint = '/login']` - The path of the challenge assertion
endpoint.
- `[challengeEndpoint = '/response']` - The path of the challenge response
endpoint.
- `[logoutEndpoint = '/logout']` - The path of the logout endpoint.

Returns a new client instance.

**`async client.register(data)`**

Completes a start-to-finish registration of a new authenticator at the remote
service with the following steps:

1. Fetch a register credential challenge from the remote server's
`credentialEndpoint`.
2. Prompt the [Credentials Management API][cred-mgmt-api] to generate a new
local credential.
   - The Credentials Management API prompts the user for consent.
   - The challenge is signed using the user-selected method and returned.
3. The signed challenge is returned to the remote server's `challengeEndpoint`.

Returns the response of the request to the `challengeEndpoint`.

**`async client.login(data)`**

Completes a start-to-finish assertion challenge on a previously registered
remote service with the following steps:

1. Fetch an assertion challenge from the remote server's `assertionEndpoint`.
2. Prompt the [Credentials Management API][cred-mgmt-api] to get an existing
local credential and sign the response.
   - The Credentials Management API prompts the user for consent.
   - The challenge is signed and returned.
3. The signed challenge is returned to the remote server's `challengeEndpoint`.

Returns the response of the request to the `challengeEndpoint`.

**`async client.logout()`**

Destroys the current session on the remote server. Returns the result of the
request to the `logoutEndpoint`.

## Maintainers

[@Terrahop](https://github.com/Terrahop)

[@EternalDeiwos](https://github.com/EternalDeiwos)

[@christiansmith](https://github.com/christiansmith)

Originally adapted from [fidoalliance/webauthn-demo](https://github.com/fido-alliance/webauthn-demo).

## Contributing

### Issues

* Please file [issues](https://github.com/strangerlabs/webauthn/issues) :)
* When writing a bug report, include relevant details such as platform, version, relevant data, and stack traces
* Ensure to check for existing issues before opening new ones
* Read the documentation before asking questions
* It is strongly recommended to open an issue before hacking and submitting a PR

### Pull requests

#### Policy

* We're not presently accepting *unsolicited* pull requests
* Create an issue to discuss proposed features before submitting a pull request
* Create an issue to propose changes of code style or introduce new tooling
* Ensure your work is harmonious with the overall direction of the project
* Ensure your work does not duplicate existing effort
* Keep the scope compact; avoid PRs with more than one feature or fix
* Code review with maintainers is required before any merging of pull requests
* New code must respect the style guide and overall architecture of the project
* Be prepared to defend your work

#### Style guide

* [Conventional Changelog](https://github.com/conventional-changelog/conventional-changelog)
* [ECMAScript](https://tc39.github.io/ecma262/)
* [Standard JavaScript](https://standardjs.com)
* [Standard README](https://github.com/RichardLitt/standard-readme)
* [jsdoc](https://jsdoc.app)

#### Code reviews

* required before merging PRs
* reviewers MUST run and test the code under review

### Tests

Run the test suite with `npm test`.

### Code of conduct

* @strangerlabs/webauthn follows the [Contributor Covenant](http://contributor-covenant.org/version/1/3/0/) Code of Conduct.

## License

MIT © 2019 Stranger Labs, Inc.
