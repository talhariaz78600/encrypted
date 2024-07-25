const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { create } = require('xmlbuilder2');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');

const app = express();
const port = 4000;

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
    // Parse the incoming XML
    const doc = new DOMParser().parseFromString(xmlData, 'text/xml');
    const serializer = new XMLSerializer();

    // Process each child element of the root to sign its content
    Array.from(doc.documentElement.childNodes).forEach(node => {
      if (node.nodeType === 1) {  // Only element nodes
        const originalContent = node.textContent.trim();
        const signedContent = signData(originalContent);
        // Clear existing content and append the signed content only
        node.textContent = '';
        const signedNode = doc.createElement('SignedContent');
        signedNode.textContent = signedContent;
        node.appendChild(signedNode);
      }
    });

    // Serialize the modified XML document to a string
    const signedXmlData = serializer.serializeToString(doc);

    // Encrypt the password and certificate
    const encryptedPassword = encryptData(password);
    const encryptedCertificate = encryptData(certificate);

    // Construct the SOAP-like XML response with signed data and encrypted fields
    const soapEnvelope = create({ version: '1.0', encoding: 'UTF-8' })
      .ele('Envelope')
      .ele('Header').up()
      .ele('Body')
      .ele('SignedData')
      .ele('XmlData').dat(signedXmlData).up()
      .ele('EncryptedPassword').txt(encryptedPassword).up()
      .ele('EncryptedCertificate').txt(encryptedCertificate).up()
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
