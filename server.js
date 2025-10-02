import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
app.use(bodyParser.json());

// Environment Variables in Render
const PRIVATE_KEY = process.env.PRIVATE_KEY;         // Your RSA private key (PEM format)
const PABBLY_WEBHOOK = process.env.PABBLY_WEBHOOK;   // Pabbly webhook URL

// --- Utility: RSA-OAEP SHA256 decryption of AES key ---
function decryptAESKey(encrypted_aes_key) {
  return crypto.privateDecrypt(
    {
      key: PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"   // 🔑 enforce SHA-256 (required by WhatsApp Flows)
    },
    Buffer.from(encrypted_aes_key, "base64")
  );
}

// --- Utility: AES decryption of Flow payload ---
function decryptFlowData(aesKey, ivB64, encrypted_flow_data) {
  const iv = Buffer.from(ivB64, "base64");
  const encBuf = Buffer.from(encrypted_flow_data, "base64");

  try {
    // AES-GCM (default used by WhatsApp)
    const tag = encBuf.slice(encBuf.length - 16);
    const ciphertext = encBuf.slice(0, encBuf.length - 16);
    const decipher = crypto.createDecipheriv(
      aesKey.length === 16 ? "aes-128-gcm" :
      aesKey.length === 24 ? "aes-192-gcm" : "aes-256-gcm",
      aesKey,
      iv
    );
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    // Fallback to AES-CBC (older payloads)
    const decipher = crypto.createDecipheriv(
      aesKey.length === 16 ? "aes-128-cbc" :
      aesKey.length === 24 ? "aes-192-cbc" : "aes-256-cbc",
      aesKey,
      iv
    );
    const raw = Buffer.concat([decipher.update(encBuf), decipher.final()]);
    const pad = raw[raw.length - 1];
    return raw.slice(0, raw.length - pad);
  }
}

// --- Health Check (Meta expects decrypted payload in Base64) ---
app.post("/", (req, res) => {
  try {
    const { initial_vector, encrypted_flow_data, encrypted_aes_key } = req.body;

    if (!initial_vector || !encrypted_flow_data || !encrypted_aes_key) {
      return res.status(400).send("Missing fields");
    }

    const aesKey = decryptAESKey(encrypted_aes_key);
    const plaintext = decryptFlowData(aesKey, initial_vector, encrypted_flow_data);

    // ✅ Return decrypted JSON string encoded once in Base64
    res.status(200).send(plaintext.toString("base64"));
  } catch (err) {
    res.status(500).send("Error: " + err.message);
  }
});

// --- Flow Webhook (real data -> forward to Pabbly) ---
app.post("/webhook", async (req, res) => {
  try {
    const { initial_vector, encrypted_flow_data, encrypted_aes_key } = req.body;

    if (!initial_vector || !encrypted_flow_data || !encrypted_aes_key) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const aesKey = decryptAESKey(encrypted_aes_key);
    const plaintext = decryptFlowData(aesKey, initial_vector, encrypted_flow_data);

    let data;
    try {
      data = JSON.parse(plaintext.toString("utf8"));
    } catch (err) {
      return res.status(500).json({
        error: "Failed to parse decrypted JSON",
        raw: plaintext.toString("utf8")
      });
    }

    // Forward decrypted JSON to Pabbly
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

// --- Service Check (Render test) ---
app.get("/", (req, res) => res.send("WhatsApp Flow Decryption Service is running"));

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
