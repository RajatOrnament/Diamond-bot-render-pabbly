import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();
app.use(bodyParser.json({ limit: "5mb" }));

const PRIVATE_KEY = process.env.PRIVATE_KEY;

// AES decrypt utility
function decryptFlowData(aesKey, ivB64, encrypted_flow_data) {
  const iv = Buffer.from(ivB64, "base64");
  const encBuf = Buffer.from(encrypted_flow_data, "base64");

  try {
    // AES-GCM (preferred)
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

// --- Health Check ---
app.post("/", (req, res) => {
  try {
    const { initial_vector, encrypted_flow_data, encrypted_aes_key } = req.body;

    if (!initial_vector || !encrypted_flow_data || !encrypted_aes_key) {
      return res.status(400).send("Missing fields");
    }

    // Decrypt AES key
    const aesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    // Decrypt Flow data
    const plaintext = decryptFlowData(aesKey, initial_vector, encrypted_flow_data);

    // ✅ Base64 encode plaintext JSON
    const base64Response = Buffer.from(plaintext).toString("base64");

    // 🔎 Log what we're sending back
    console.log("✅ Health Check Decrypted JSON:", plaintext.toString("utf8"));
    console.log("✅ Health Check Base64 Response:", base64Response);

    // Send plain Base64
    res.set("Content-Type", "text/plain");
    res.status(200).send(base64Response);

  } catch (err) {
    console.error("❌ Health check error:", err);
    res.status(500).send("Error: " + err.message);
  }
});

// --- Simple Alive Check ---
app.get("/", (req, res) => res.send("✅ Service is running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
