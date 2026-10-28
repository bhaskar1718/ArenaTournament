# Arena Tournament Website

React + FastAPI + PostgreSQL starter. Includes signup email OTP, login, password reset OTP, tournaments, Razorpay order/signature verification, and admin monitoring. Withdrawals are intentionally not included.

## Windows setup
1. Install Python 3.11+, Node.js LTS, and Docker Desktop.
2. Extract this ZIP and open PowerShell in the project directory.
3. `Copy-Item .env.example .env`, then edit `.env`.
4. Start PostgreSQL: `docker compose up -d db`
5. Backend terminal:
   `cd backend`
   `py -m venv .venv`
   `\.venv\Scripts\Activate.ps1`
   `pip install -r requirements.txt`
   `uvicorn app.main:app --reload`
6. Frontend terminal: `cd frontend`, `npm install`, `npm run dev`.
7. Open http://localhost:5173. API docs: http://127.0.0.1:8000/docs.

Configure SMTP credentials for real email delivery. Configure Razorpay TEST keys first. Set `ADMIN_EMAIL` to an email you control before signup; that verified account gets admin access. Change `JWT_SECRET`. Never commit `.env`.

## Before production
Use managed PostgreSQL, HTTPS, secret manager, backups, monitoring, rate limiting, security testing, privacy/terms pages and Razorpay webhooks. Obtain Razorpay approval and confirm applicable Indian/state gaming, prize, tax and consumer requirements before accepting live entry fees or payouts. A signature callback is not a substitute for production webhook reconciliation. No withdrawals are included.
