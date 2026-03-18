# Node.js Board App

A full-stack bulletin board web application built with **Node.js**, **Express**, and **MongoDB**. It provides authentication, posts and comments, file uploads, and real-time chat.

## DEMO

- **Live URL**: (Add your public URL here if deployed)
- Features: sign up / sign in, create and manage posts, comment and reply, upload images, and chat in real time.

## Features

- **Authentication & user accounts** – Sign up, login, logout, password reset, find ID.
- **Board** – Create, read, update, delete posts; like posts.
- **Comments** – Comments and threaded replies for each post.
- **Real-time chat** – 1:1 chat using Socket.io and Server-Sent Events.
- **File uploads** – Upload up to 10 image files per request to `public/image/`.

## Architecture

- **Client (Web browser)**
  - EJS templates rendered on the server
  - HTML/CSS/JavaScript
  - Socket.io client for real-time chat

- **Server (Express.js on Node.js 20)**
  - Authentication and sessions (Passport.js, express-session, bcrypt)
  - Board & comments API
  - File upload API using Multer → `public/image/`
  - Real-time messaging via Socket.io + SSE
  - Email sending with Nodemailer (SMTP configured via environment variables)

- **Database (MongoDB 7.0)**
  - `login` – user accounts
  - `post` – posts
  - `comments` – comments and replies
  - `chatroom` – chat rooms and members
  - `message` – chat messages
  - `counter` – sequence counter for posts

## Tech Stack

- **Backend**: Node.js, Express.js, Passport.js, MongoDB (native driver & Mongoose), Socket.io, Multer, Nodemailer
- **Frontend**: EJS, HTML, CSS, JavaScript, Bootstrap
- **Infra**: Docker, Docker Compose, MongoDB 7.0

## Docker (Development / Demo)

This repository includes a simple Docker Compose setup for local or demo use.

- **MongoDB**: `mongo:7.0` (container `node_board_mongodb`, exposed on host `27018` → container `27017`)
- **App**: Node.js app container (`node_board_app`), exposed on **http://localhost:3002** (host) → `3002:3000`.

### Quick start

```bash
# 1. Create .env from template
cp .env.example .env

# 2. Build & start with Docker Compose
cd Node.js_board
docker compose up -d --build

# 3. Open the app
http://localhost:3002
```

### Environment variables (example)

```env
DB_URL=mongodb://admin:password@mongodb:27017/server?authSource=admin
SESSION_SECRET=your-super-secret-session-key
EMAIL_HOST=smtp.example.com
EMAIL_PORT=465
EMAIL_USER=your-email@example.com
EMAIL_PASS=your-app-password
PORT=3000
```

## Open-source checklist (before publishing)

- **Secrets**: Do not commit `.env`, SMTP credentials, or session secrets. Use `.env.example` only.
- **Uploads**: Keep `public/image/` out of git. Validate file type/size (implemented) and consider virus scanning in production.
- **Sessions**: Set a strong `SESSION_SECRET` and use a persistent session store in production (Redis/Mongo store).
- **Authorization**: Ensure only authors can delete/edit content (delete route is restricted).
- **CSRF & rate limiting**: CSRF tokens are required for state-changing requests, and auth/email routes are rate-limited.

## License

ISC
