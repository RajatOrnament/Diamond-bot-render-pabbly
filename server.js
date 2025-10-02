import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
app.use(bodyParser.json());

// Load secrets from Render env variables
const PRIVATE_KEY = process.env.PRIVATE_KEY;         // RSA private key (PEM format, including -----BEGIN PRIVATE KEY-----)
const PABBLY_WEBHOOK = process.env.PABBLY_WEBHOOK;   // Pabbly webhook URL

// --- Health Check Endpoints ---
app.get("/", (req, res) => {
  res.send("WhatsApp Flow Decryption Service is running");
});

// Meta runs health check with POST /, so respond 200 OK
app.post("/", (req, res) => {
  res.status(200).json({ status: "ok" });
});

// --- Webhook Decryption ---
app.post("/webhook", async (req, res) => {
  try {
    const { initial_vector, encrypted_flow_data, encrypted_aes_key } = req.body;

    if (!initial_vector || !encrypted_flow_data || !encrypted_aes_key) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // 1. Decrypt AES key (RSA OAEP SHA-256, fallback SHA-1)
    let aesKey;
    try {
      aesKey = crypto.privateDecrypt(
        {
          key: PRIVATE_KEY,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256"
        },
        Buffer.from(encrypted_aes_key, "base64")
      );
    } catch (e1) {
      aesKey = crypto.privateDecrypt(
        {
          key: PRIVATE_KEY,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING // default OAEP-SHA1
        },
        Buffer.from(encrypted_aes_key, "base64")
      );
    }

    // 2. Decrypt Flow data (AES-GCM first, fallback to AES-CBC)
    const iv = Buffer.from(initial_vector, "base64");
    const encBuf = Buffer.from(encrypted_flow_data, "base64");
    let plaintext;

    try {
      // AES-GCM: ciphertext || 16-byte tag
      const tag = encBuf.slice(encBuf.length - 16);
      const ciphertext = encBuf.slice(0, encBuf.length - 16);
      const decipher = crypto.createDecipheriv(
        aesKey.length === 16 ? "aes-128-gcm" : aesKey.length === 24 ? "aes-192-gcm" : "aes-256-gcm",
        aesKey,
        iv
      );
      decipher.setAuthTag(tag);
      plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (err) {
      // Fallback AES-CBC + PKCS#7
      const decipher = crypto.createDecipheriv(
        aesKey.length === 16 ? "aes-128-cbc" : aesKey.length === 24 ? "aes-192-cbc" : "aes-256-cbc",
        aesKey,
        iv
      );
      const raw = Buffer.concat([decipher.update(encBuf), decipher.final()]);
      const pad = raw[raw.length - 1];
      plaintext = raw.slice(0, raw.length - pad);
    }

    let data;
    try {
      data = JSON.parse(plaintext.toString("utf8"));
    } catch (err) {
      return res.status(500).json({
        error: "Failed to parse decrypted JSON",
        raw: plaintext.toString("utf8")
      });
    }

    // 3. Forward decrypted JSON to Pabbly
    await fetch(PABBLY_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });

    res.json({ status: "ok", forwarded: true, data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
