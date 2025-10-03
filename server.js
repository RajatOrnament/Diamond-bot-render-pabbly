import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();

// Middleware: parse both JSON and urlencoded bodies
app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "5mb" }));

// Load secrets from environment
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const PABBLY_WEBHOOK = process.env.PABBLY_WEBHOOK;

// --- Utility: RSA-OAEP SHA256 decryption of AES key ---
function decryptAESKey(encrypted_aes_key) {
  return crypto.privateDecrypt(
    {
      key: PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    },
    Buffer.from(encrypted_aes_key, "base64")
  );
}

// --- Utility: AES decryption ---
function decryptFlowData(aesKey, ivB64, encrypted_flow_data) {
  const iv = Buffer.from(ivB64, "base64");
  const encBuf = Buffer.from(encrypted_flow_data, "base64");

  try {
    // AES-GCM
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
    // AES-CBC fallback
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

// --- Webhook (for Pabbly → Render) ---
app.post("/webhook", async (req, res) => {
  try {
    console.log("BODY RECEIVED:", req.body); // Debug log

    // Support both JSON body and form-urlencoded
    const initial_vector =
      req.body.initial_vector || req.body["initial_vector"];
    const encrypted_flow_data =
      req.body.encrypted_flow_data || req.body["encrypted_flow_data"];
    const encrypted_aes_key =
      req.body.encrypted_aes_key || req.body["encrypted_aes_key"];

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

    // Forward to Pabbly webhook (optional)
    if (PABBLY_WEBHOOK) {
      await fetch(PABBLY_WEBHOOK, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
    }

    res.json({ status: "ok", data });
  } catch (err) {
    console.error("Decrypt error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Health check route
app.get("/", (req, res) => res.send("✅ WhatsApp Flow Decryption Service is running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
