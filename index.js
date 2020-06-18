const fsPromises = require('fs').promises
const path = require('path')
const { promisify } = require('util')
const acme = require('acme-client')
const http = require('http')
const debug = require('debug')('acme-simple-auto')

const DEFAULT_RENEW_THRESHOLD_DAYS = 14
const DAY_IN_MS = 24 * 60 * 60 * 1000

async function obtainCertificate({
  accountKey,
  commonName,
  email,
  serverHost,
  serverPort,
  directoryUrl,
}) {
  const tokenMap = new Map()

  if (!serverHost) {
    serverHost = commonName
  }

  if (!serverPort) {
    serverPort = 80
  }

  async function challengeCreateFn(authz, challenge, keyAuthorization) {
    if (challenge.type !== 'http-01') {
      throw new Error(`Unsupported ACME challenge type ${challenge.type}`)
    }
    tokenMap.set(challenge.token, keyAuthorization)
  }

  async function challengeRemoveFn(authz, challenge, keyAuthorization) {
    if (challenge.type !== 'http-01') {
      throw new Error(`Unsupported ACME challenge type ${challenge.type}`)
    }
    tokenMap.delete(challenge.token, keyAuthorization)
  }

  const wellKnownPath = '/.well-known/acme-challenge/'

  const server = http.createServer((req, res) => {
    debug(`HTTP request received: ${req.method} ${req.url}`)
    if (req.method === 'GET' && req.url.startsWith(wellKnownPath)) {
      const token = req.url.split(wellKnownPath)[1]
      if (tokenMap.has(token)) {
        res.statusCode = 200
        res.setHeader('Content-Type', 'application/octet-stream')
        res.end(tokenMap.get(token))
      }
    }

    res.statusCode = 404
    res.end()
  })

  const listen = promisify(server.listen).bind(server)
  const closeServer = promisify(server.close).bind(server)

  await listen(serverPort, serverHost)
  debug(`ACME challenge server running at http://${serverHost}:${serverPort}/`)

  const client = new acme.Client({
    directoryUrl,
    accountKey,
  })

  const [key, csr] = await acme.forge.createCsr({
    commonName,
  })

  debug('Performing certificate request...')
  const cert = await client.auto({
    csr,
    email,
    termsOfServiceAgreed: true,
    challengeCreateFn,
    challengeRemoveFn,
    challengePriority: ['http-01'],
  })

  await closeServer()

  return { key, cert }
}

module.exports = async function ({
  dataDir,
  commonName,
  email,
  serverHost,
  serverPort,
  production = false,
  renewThresholdDays = DEFAULT_RENEW_THRESHOLD_DAYS,
  directoryUrl,
}) {
  try {
    await fsPromises.mkdir(dataDir, { mode: 0o700 })
  } catch (err) {
    if (err.code !== 'EEXIST') {
      throw err
    }
  }

  const accountKeyPath = path.join(dataDir, 'account.pem')
  const privateKeyPath = path.join(dataDir, 'key.pem')
  const certPath = path.join(dataDir, 'cert.pem')

  let existingKey
  let existingCert
  try {
    existingKey = await fsPromises.readFile(privateKeyPath)
    existingCert = await fsPromises.readFile(certPath)
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw err
    }
  }

  if (existingKey && existingCert) {
    debug(
      `Read private key from '${privateKeyPath}' and certificate from '${certPath}'.`,
    )

    const certInfo = await acme.forge.readCertificateInfo(existingCert)
    debug(
      `Certificate valid from ${certInfo.notBefore.toUTCString()} to ${certInfo.notAfter.toUTCString()}.`,
    )
    const willExpireSoon =
      Date.now() > certInfo.notAfter.getTime() - renewThresholdDays * DAY_IN_MS
    if (!willExpireSoon) {
      return { key: existingKey, cert: existingCert }
    } else {
      debug(
        `Certificate expires sooner than ${renewThresholdDays} days. Renewing.`,
      )
    }
  }

  let accountKey
  try {
    accountKey = await fsPromises.readFile(accountKeyPath)
    debug(`Read account key from '${accountKeyPath}'.`)
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw err
    }
    accountKey = await acme.forge.createPrivateKey()
    await fsPromises.writeFile(accountKeyPath, accountKey, { mode: 0o700 })
    debug(`Generated and saved account key at '${accountKeyPath}'.`)
  }

  if (!directoryUrl) {
    directoryUrl = production
      ? acme.directory.letsencrypt.production
      : acme.directory.letsencrypt.staging
  }

  const { key, cert } = await obtainCertificate({
    accountKey,
    commonName,
    email,
    serverHost,
    serverPort,
    directoryUrl,
  })

  await fsPromises.writeFile(privateKeyPath, key, { mode: 0o700 })
  await fsPromises.writeFile(certPath, cert, { mode: 0o700 })
  debug(
    `Saved private key to '${privateKeyPath}' and certificate to '${certPath}'.`,
  )

  return { key, cert }
}

module.exports.directory = acme.directory
