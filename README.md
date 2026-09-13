# HacKerSANDEEP Luxury Social — Real-Time Edition

A full-stack upgrade of the luxury social-chat UI.

## Included
- Server-side registration and login
- bcrypt password hashing
- HttpOnly cookie authentication
- Real-time Socket.IO messaging
- Online/offline presence
- Direct conversations
- Group creation
- Server-persisted messages
- Image/video/audio/PDF/text upload endpoint (10 MB limit)
- WebRTC audio/video call signaling with STUN
- Responsive luxury/Instagram-inspired interface
- Existing blue guitar artwork retained as `public/1.png`

## Run locally
1. Install Node.js 18+.
2. Open a terminal in this folder.
3. Run `npm install`.
4. Copy `.env.example` to `.env` and set a strong `JWT_SECRET`.
5. Run `npm start`.
6. Open `http://localhost:3000`.

For camera/microphone access, use HTTPS in production. `localhost` is treated as a secure context by modern browsers for local development.

## Production notes
This build uses a small JSON datastore so it can run without a database server. For production, replace `data/db.json` with PostgreSQL/MySQL/MongoDB, put the app behind HTTPS, use a real secret manager, add rate limiting, CSRF protection as appropriate, virus/file scanning, object storage, moderation, and a TURN server for reliable WebRTC calls across restrictive networks.

Never commit `data/db.json`, `.env`, or uploaded files.
