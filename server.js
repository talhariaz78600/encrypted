
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { create } = require('xmlbuilder2');

const app = express();
const port = 4000;

const cors = require("cors")
app.use(cors())
// Middleware to parse JSON bodies
app.use(express.json());

// Shared secret key for HMAC (symmetric key)
const secretKey = 'talhariaz7860';

// Encryption key and IV (initialization vector) for AES
const encryptionKey = crypto.createHash('sha256').update('my_encryption_key').digest('base64').substr(0, 32);
const iv = crypto.randomBytes(16);

// Function to sign data using HMAC
const signData = (data) => {
  return jwt.sign({ data }, secretKey, { algorithm: 'HS256' });
};

// Function to encrypt data
const encryptData = (data) => {
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);
  let encrypted = cipher.update(data, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
};

// Route to handle data signing and encryption
app.post('/sign', (req, res) => {
  const { xmlData, password, certificate } = req.body;

  if (!xmlData || !password || !certificate) {
    return res.status(400).send('Missing required fields: xmlData, password, or certificate');
  }

  try {
    // Sign the XML data using HMAC and JWT
    const signedToken = signData(xmlData);

    // Encrypt the password and certificate
    const encryptedPassword = encryptData(password);
    const encryptedCertificate = encryptData(certificate);

    // Wrap the signed token, encrypted password, and encrypted certificate in a SOAP-like XML structure
    const soapEnvelope = create({ version: '1.0', encoding: 'UTF-8' })
      .ele('soapenv:Envelope', {
        'xmlns:soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
        'xmlns:fu': 'http://www.fu.gov.si/',
        'xmlns:xd': 'http://www.w3.org/2000/09/xmldsig#'
      })
      .ele('soapenv:Header').up()
      .ele('soapenv:Body')
      .ele('fu:SignedData')
      .ele('fu:Token').txt(signedToken).up()
      .ele('fu:EncryptedPassword').txt(encryptedPassword).up()
      .ele('fu:EncryptedCertificate').txt(encryptedCertificate).up()
      .up()
      .up()
      .up()
      .end({ prettyPrint: true });

    res.set('Content-Type', 'application/xml');
    res.send(soapEnvelope);
  } catch (error) {
    console.error('Error signing and encrypting data:', error);
    res.status(500).json({ error: 'Failed to sign and encrypt data', details: error.message });
  }
});

// Health check route
app.get("/", (req, res) => {
  res.status(200).json({ message: `server is running on port ${port}` });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
