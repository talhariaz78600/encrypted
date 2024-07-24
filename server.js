const express = require('express');
const crypto = require('crypto');
const { message } = require('statuses');

const app = express();
const port = 5000;

// Middleware to parse JSON bodies
app.use(express.json());

// Route to handle separate encryption
app.post('/encrypt', (req, res) => {
    const { password, code, certificate } = req.body;

    try {

        if (!password || !code || !certificate) {
            return res.status(400).send('Missing required fields: password, code, or certificate');
        }
        const encryptData = (data) => {
            const encryptionKey = crypto.randomBytes(32);
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
            let encrypted = cipher.update(data, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            return encrypted;
        };

        // Encrypt each piece of data separately
        const encryptedPassword = encryptData(password);
        const encryptedCode = encryptData(code);
        const encryptedCertificate = encryptData(certificate);

        // Return the encrypted data, keys, and IVs (for demonstration purposes)
        res.status(200).json({
            encryptedPassword: encryptedPassword,
            encryptedCode: encryptedCode,
            encryptedCertificate: encryptedCertificate,
        });
    } catch (error) {
        res.json({ error: error.message });
    }


    // Function to encrypt data

});


app.get("/", (req, res)=>{
    res.status(200).json({message:`server is running ${port}`})
})
// Start the server
app.listen(port, () => {
    console.log(`Server is running on ${port}`);
});
