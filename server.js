import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
app.use(bodyParser.json({ limit: "5mb" }));

const PRIVATE_KEY = process.env.PRIVATE_KEY;
const PABBLY_WEBHOOK = process.env.PABBLY_WEBHOOK;

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
  } catch {
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

// --- Health Check (Meta will POST /) ---
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

    // Decrypt flow data
    const plaintext = decryptFlowData(aesKey, initial_vector, encrypted_flow_data);

    // Log for debugging
    console.log("✅ Health Check Decrypted JSON:", plaintext.toString("utf8"));

    // Respond with only Base64 string
    const base64Response = Buffer.from(plaintext).toString("base64");
    res.set("Content-Type", "text/plain");
    res.status(200).send(base64Response);

  } catch (err) {
    console.error("❌ Health check error:", err.message);
    res.status(500).send("Error: " + err.message);
  }
});

// --- Real Flow submissions (Meta → Pabbly) ---
app.post("/webhook", async (req, res) => {
  try {
    const { initial_vector, encrypted_flow_data, encrypted_aes_key } = req.body;
    if (!initial_vector || !encrypted_flow_data || !encrypted_aes_key) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const aesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    const plaintext = decryptFlowData(aesKey, initial_vector, encrypted_flow_data);

    let data;
    try {
      data = JSON.parse(plaintext.toString("utf8"));
    } catch {
      return res.status(500).json({ error: "Invalid decrypted JSON", raw: plaintext.toString("utf8") });
    }

    console.log("📩 Decrypted Flow submission:", data);

    // Forward decrypted JSON to Pabbly webhook if configured
    if (PABBLY_WEBHOOK) {
      await fetch(PABBLY_WEBHOOK, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
    }

    res.json({ status: "ok", data });

  } catch (err) {
    console.error("❌ Webhook error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// --- Alive check ---
app.get("/", (req, res) => res.send("✅ Service is running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
