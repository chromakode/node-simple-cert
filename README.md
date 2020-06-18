# node-simple-cert

A promise that automatically fetches and renews an SSL certificate via Let's Encrypt.

```js
const https = require('https')
const simpleCert = require('node-simple-cert')

const {key, cert} = await simpleCert({
  dataDir: '/private/directory',
  commonName: 'simplecert.cool',
  email: 'webmaster@simplecert.cool',
  production: true,
  serverHost: 'localhost',
  serverPort: '8080',  // you must proxy this to port 80
})

https.createServer({key, cert}, (req, res) => { ... }).listen(8081)
```

## About

This library is intended for small web services where being self-contained and easy to deploy by end users is a concern. It uses [node-acme-client](https://github.com/publishlab/node-acme-client) to automatically obtain and renew an SSL certificate using Let's Encrypt. Private keys and certificates are stored in `dataDir` with permissions restricted to the current user. Certificates are cached on disk and automatically renewed if expiring in 14 days or sooner (configurable via the `renewThresholdDays` option).

To integrate, run `simpleCert` before you initialize your `http` server. `simpleCert` creates a temporary HTTP server while it's obtaining the cert in order to respond to [ACME http-01](https://tools.ietf.org/html/rfc8555#section-8.3) challenges. This needs to be served on port 80 at the domain name specified. The easiest way to do this on Linux hosts is to proxy port 80 to a nonprivileged port (specify `serverHost` and `serverPort` to determine where this HTTP server will listen).

## Options

 - `dataDir`: Path to a directory where keys will be stored. If it does not exist it will be created.
 - `commonName`: The "common name" of the certificate (the domain name your server will be accessible from).
 - `email`: Email address for the owner of this domain (used to contact for account administration).
 - `serverHost`: Hostname to listen for ACME challenge on.
 - `serverPort`: Port to listen for ACME challenge on.
 - `production`: If unset, the [Let's Encrypt staging environment](https://letsencrypt.org/docs/staging-environment) will be used, which is appropriate for testing.
 - `renewThresholdDays`: If the stored certificate expires sooner than the specified number of days, it will be renewed.
 - `directoryUrl`: Used to specify a custom ACME directory other than Let's Encrypt.
