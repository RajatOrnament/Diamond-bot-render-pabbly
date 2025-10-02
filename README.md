# Diamond Decrypt – WhatsApp Flow Decryption Middleware

A simple Node.js service to decrypt WhatsApp Flow `data_exchange` payloads and forward clean JSON to Pabbly Connect.

## 🚀 How It Works
1. WhatsApp Flow sends encrypted payload (AES+RSA) to this service.
2. Service decrypts using your **RSA private key**.
3. Forwards clean JSON (e.g. `shape`, `min_carat`, `color`, etc.) to Pabbly webhook.

## 🛠 Setup on Render
1. Fork or upload this repo to GitHub.
2. Create a **Web Service** in Render.
3. Connect your GitHub repo.
4. Add **Environment Variables** in Render:
   - `PRIVATE_KEY` → your RSA private key (PEM format, including `-----BEGIN PRIVATE KEY-----` and `END PRIVATE KEY-----`)
   - `PABBLY_WEBHOOK` → your Pabbly webhook URL
5. Deploy! 🎉

## 🔗 Usage
- Set your WhatsApp Flow `data_exchange` URI to:
