# Timing Secure Web App

This package wraps your assessment in a login-protected web app and logs:
- successful logins
- failed login attempts
- access requests

## What is included
- `assessment.html` -> your current full Timing Language & Safety Matrix
- `server.js` -> Express server with login, session handling and admin dashboard
- `data/` -> JSON data store for users, login attempts and access requests
- `public/admin.js` and `public/styles.css` -> dashboard UI files

## Setup
1. Install Node.js 18+.
2. Open a terminal in this folder.
3. Run:
   - `npm install`
   - Windows PowerShell:
     - `$env:OWNER_EMAIL="your@email.com"`
     - `$env:OWNER_PASSWORD="ChooseAStrongPassword123!"`
     - `$env:OWNER_NAME="Dainyel Rooi"`
     - `$env:SESSION_SECRET="change-this-to-a-long-random-string"`
     - `npm start`
   - macOS/Linux:
     - `export OWNER_EMAIL="your@email.com"`
     - `export OWNER_PASSWORD="ChooseAStrongPassword123!"`
     - `export OWNER_NAME="Dainyel Rooi"`
     - `export SESSION_SECRET="change-this-to-a-long-random-string"`
     - `npm start`
4. Open `http://localhost:3000`.

## How it works
- Users must log in before they can open the assessment.
- Unknown users and wrong passwords are logged in `data/login-attempts.json`.
- New users can submit an access request from the login page.
- As owner/admin, you can log in and open `/admin` to review requests and create approved users.

## Important
- This is self-hosted. You do not need a third-party cloud platform to run it.
- If you want others outside your local network to access it, you must host this on a server or securely expose your machine online.
- Change the default owner credentials before use.
- For production use, place it behind HTTPS and set `cookie.secure = true` in `server.js`.

## Source file used
- `Timing-Language-Safety-Matrix-FULL-UPDATED-v3-no-dropdown-colors.html`
