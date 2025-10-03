import crypto from "crypto";
import fs from "fs";

// Load private key
const PRIVATE_KEY = fs.readFileSync("private_key.pem", "utf8");

// Replace with values you got from Meta's test payload (health check)
const encryptedAESKeyB64 = "<paste from encrypted_aes_key>";
const encryptedFlowDataB64 = "<paste from encrypted_flow_data>";
const ivB64 = "<paste from initial_vector>";

// 1. Decrypt AES key (RSA-OAEP SHA256)
const aesKey = crypto.privateDecrypt(
  {
    key: PRIVATE_KEY,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256"
  },
  Buffer.from(encryptedAESKeyB64, "base64")
);

// 2. Try AES-GCM decryption
let plaintext;
try {
  const encBuf = Buffer.from(encryptedFlowDataB64, "base64");
  const tag = encBuf.slice(encBuf.length - 16);
  const ciphertext = encBuf.slice(0, encBuf.length - 16);
  const decipher = crypto.createDecipheriv(
    aesKey.length === 16 ? "aes-128-gcm" :
    aesKey.length === 24 ? "aes-192-gcm" : "aes-256-gcm",
    aesKey,
    Buffer.from(ivB64, "base64")
  );
  decipher.setAuthTag(tag);
  plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
} catch (e) {
  // fallback AES-CBC
  const decipher = crypto.createDecipheriv(
    aesKey.length === 16 ? "aes-128-cbc" :
    aesKey.length === 24 ? "aes-192-cbc" : "aes-256-cbc",
    aesKey,
    Buffer.from(ivB64, "base64")
  );
  const raw = Buffer.concat([decipher.update(Buffer.from(encryptedFlowDataB64, "base64")), decipher.final()]);
  const pad = raw[raw.length - 1];
  plaintext = raw.slice(0, raw.length - pad);
}

console.log("🔓 Decrypted:", plaintext.toString("utf8"));
console.log("📦 Base64 Response:", Buffer.from(plaintext.toString("utf8")).toString("base64"));
