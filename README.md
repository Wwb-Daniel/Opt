# OTP Server (Free, Render-ready)

Endpoints:
- POST /sendOtp { email }
- POST /verifyOtp { email, code }

Tech:
- Node 20, Express, Nodemailer (Gmail App Password), Firebase Admin, Firestore

## Run locally (Windows PowerShell)
```
npm install
$env:FIREBASE_SERVICE_ACCOUNT_FILE="c:\Users\Home\chatapp\omniplay-30be1-firebase-adminsdk-fbsvc-5c2e6b37fa.json";
$env:GMAIL_USER="<your_gmail>@gmail.com";
$env:GMAIL_PASS="<app_password_16_chars>";
$env:PORT="3001";
node index.js
```

## Deploy to Render (Free)
1) Push this folder to GitHub (root: otp-server). Ensure secrets are NOT committed.
   - .gitignore excludes node_modules, logs, secret/*, etc.
2) In Render → New → Web Service
   - Root directory: `otp-server`
   - Start command: `node index.js`
   - Runtime: Node 20, Plan: Free
3) Environment variables in Render → Settings → Environment
   - PORT=10000
   - GMAIL_USER=your_gmail
   - GMAIL_PASS=your_app_password
   - FIREBASE_SERVICE_ACCOUNT_BASE64=<paste the base64 of your service account JSON>

### Generate Base64 of service account (PowerShell)
```
[Convert]::ToBase64String([IO.File]::ReadAllBytes("c:\Users\Home\chatapp\omniplay-30be1-firebase-adminsdk-fbsvc-5c2e6b37fa.json"))
```
Copy the output string and paste it into Render as FIREBASE_SERVICE_ACCOUNT_BASE64.

## CORS
CORS is open by default. Restrict if needed.

## Security
- Never commit service-account JSON or app passwords.
- Use Gmail App Password (not your regular password).
