
# JARVIS AI Backend

## Requirements
- Node.js 20+
- MongoDB Atlas account
- OpenAI API account

## Installation

npm install

## Environment

Copy .env.example to .env.

Set:
MONGODB_URI
MONGODB_DB
JWT_SECRET
OPENAI_API_KEY
OPENAI_MODEL

## Run

npm start

## API Routes

GET    /
GET    /api/health

POST   /api/auth/register
POST   /api/auth/login
GET    /api/me

POST   /api/chat

GET    /api/conversations
GET    /api/conversations/:id/messages

GET    /api/memories
POST   /api/memories
DELETE /api/memories/:id
