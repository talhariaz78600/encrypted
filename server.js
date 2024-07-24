const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

// Middleware to parse JSON bodies
app.use(express.json());

// Shared secret key (for demonstration purposes only)
const secretKey = '3463764756476538476512';

// Function to sign data
const signData = (data) => {
  // Sign the data with the shared secret key
  return jwt.sign({ data }, secretKey, { algorithm: 'HS256' });
};

// Route to handle data signing
app.post('/sign', (req, res) => {
  const { password, certificate, xmlData } = req.body;

  if (!password || !certificate || !xmlData) {
    return res.status(400).send('Missing required fields: password, certificate, or xmlData');
  }

  try {
    // Sign each piece of data separately
    const signedPassword = signData(password);
    const signedCertificate = signData(certificate);
    const signedXmlData = signData(xmlData);

    // Return the signed data
    res.json({
      signedPassword,
      signedCertificate,
      signedXmlData,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to sign data', details: error.message });
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
