
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { MongoClient, ObjectId } = require("mongodb");
const OpenAI = require("openai");
const { rateLimit } = require("express-rate-limit");

const app = express();

const PORT = process.env.PORT || 3000;
const DB_NAME = process.env.MONGODB_DB || "jarvis_ai";

const required = [
  "MONGODB_URI",
  "JWT_SECRET",
  "OPENAI_API_KEY"
];

for (const name of required) {
  if (!process.env[name]) {
    throw new Error(`Missing environment variable: ${name}`);
  }
}

if (process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must contain at least 32 characters.");
}

const client = new MongoClient(process.env.MONGODB_URI);
const ai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

let db;
let users;
let conversations;
let messages;
let memories;

app.disable("x-powered-by");

app.use(helmet());

const allowedOrigins = (
  process.env.FRONTEND_ORIGIN || "*"
).split(",").map(v => v.trim());

app.use(cors({
  origin(origin, callback) {
    if (
      !origin ||
      allowedOrigins.includes("*") ||
      allowedOrigins.includes(origin)
    ) {
      return callback(null, true);
    }

    callback(new Error("Origin not allowed"));
  }
}));

app.use(express.json({ limit: "100kb" }));

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

app.use(generalLimiter);

// ===================================
// UTILITIES
// ===================================

function validEmail(email) {
  return typeof email === "string" &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPassword(password) {
  return typeof password === "string" &&
    password.length >= 12 &&
    password.length <= 72;
}

function createToken(user) {
  return jwt.sign(
    { sub: user._id.toString() },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function publicUser(user) {
  return {
    id: user._id.toString(),
    email: user.email
  };
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  try {
    const token = header.slice(7);

    const payload = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    if (typeof payload.sub !== "string") {
      throw new Error("Invalid token");
    }

    req.userId = new ObjectId(payload.sub);
    next();

  } catch {
    return res.status(401).json({
      error: "Invalid or expired login session."
    });
  }
}

function validObjectId(id) {
  return typeof id === "string" &&
    ObjectId.isValid(id) &&
    new ObjectId(id).toString() === id;
}

// ===================================
// HEALTH CHECK
// ===================================

app.get("/", (req, res) => {
  res.json({
    name: "JARVIS AI Backend",
    version: "2.0.0",
    status: "online"
  });
});

app.get("/api/health", async (req, res) => {
  try {
    await db.command({ ping: 1 });

    res.json({
      status: "healthy",
      database: "connected",
      aiConfigured: Boolean(process.env.OPENAI_API_KEY)
    });
  } catch {
    res.status(503).json({
      status: "unhealthy",
      database: "unavailable"
    });
  }
});

// ===================================
// AUTHENTICATION
// ===================================

app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!validEmail(email) || !validPassword(password)) {
      return res.status(400).json({
        error: "Enter a valid email and a password of at least 12 characters."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existing = await users.findOne({
      email: normalizedEmail
    });

    if (existing) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = {
      email: normalizedEmail,
      passwordHash,
      createdAt: new Date()
    };

    const result = await users.insertOne(user);
    user._id = result.insertedId;

    return res.status(201).json({
      success: true,
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        error: "Account already exists."
      });
    }

    console.error("Registration error:", error.message);

    res.status(500).json({
      error: "Registration failed."
    });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const user = await users.findOne({
      email: email.trim().toLowerCase()
    });

    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    return res.json({
      success: true,
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    console.error("Login error:", error.message);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

app.get("/api/me", authRequired, async (req, res) => {
  const user = await users.findOne({
    _id: req.userId
  });

  if (!user) {
    return res.status(404).json({
      error: "User not found."
    });
  }

  res.json({
    user: publicUser(user)
  });
});

// ===================================
// MEMORY ENGINE
// ===================================

app.get("/api/memories", authRequired, async (req, res) => {
  const result = await memories.find({
    userId: req.userId
  })
  .sort({ createdAt: -1 })
  .limit(100)
  .toArray();

  res.json({
    memories: result.map(m => ({
      id: m._id.toString(),
      text: m.text,
      createdAt: m.createdAt
    }))
  });
});

app.post("/api/memories", authRequired, async (req, res) => {
  const text = req.body?.text;

  if (
    typeof text !== "string" ||
    !text.trim() ||
    text.length > 1000
  ) {
    return res.status(400).json({
      error: "Memory must contain 1–1000 characters."
    });
  }

  const result = await memories.insertOne({
    userId: req.userId,
    text: text.trim(),
    createdAt: new Date()
  });

  res.status(201).json({
    success: true,
    id: result.insertedId.toString()
  });
});

app.delete("/api/memories/:id", authRequired, async (req, res) => {
  if (!validObjectId(req.params.id)) {
    return res.status(400).json({
      error: "Invalid memory ID."
    });
  }

  const result = await memories.deleteOne({
    _id: new ObjectId(req.params.id),
    userId: req.userId
  });

  res.json({
    success: result.deletedCount === 1
  });
});

// ===================================
// CONVERSATION HISTORY
// ===================================

app.get("/api/conversations", authRequired, async (req, res) => {
  const result = await conversations.find({
    userId: req.userId
  })
  .sort({ updatedAt: -1 })
  .limit(50)
  .toArray();

  res.json({
    conversations: result
  });
});

app.get("/api/conversations/:id/messages", authRequired, async (req, res) => {
  if (!validObjectId(req.params.id)) {
    return res.status(400).json({
      error: "Invalid conversation ID."
    });
  }

  const conversationId = new ObjectId(req.params.id);

  const conversation = await conversations.findOne({
    _id: conversationId,
    userId: req.userId
  });

  if (!conversation) {
    return res.status(404).json({
      error: "Conversation not found."
    });
  }

  const result = await messages.find({
    conversationId,
    userId: req.userId
  })
  .sort({ createdAt: 1 })
  .limit(200)
  .toArray();

  res.json({
    messages: result.map(m => ({
      role: m.role,
      content: m.content,
      createdAt: m.createdAt
    }))
  });
});

// ===================================
// AI CHAT ENGINE
// ===================================

app.post("/api/chat", authRequired, chatLimiter, async (req, res) => {
  try {
    const { messages: inputMessages, conversationId } =
      req.body || {};

    if (
      !Array.isArray(inputMessages) ||
      inputMessages.length === 0 ||
      inputMessages.length > 20
    ) {
      return res.status(400).json({
        error: "Invalid message history."
      });
    }

    const safeMessages = [];

    for (const message of inputMessages) {
      if (
        !message ||
        !["user", "assistant"].includes(message.role) ||
        typeof message.content !== "string" ||
        !message.content.trim() ||
        message.content.length > 8000
      ) {
        return res.status(400).json({
          error: "Invalid message format."
        });
      }

      safeMessages.push({
        role: message.role,
        content: message.content
      });
    }

    const latest = safeMessages[safeMessages.length - 1];

    if (latest.role !== "user") {
      return res.status(400).json({
        error: "The latest message must be from the user."
      });
    }

    // Create or verify the conversation.
    let conversation;

    if (conversationId) {
      if (!validObjectId(conversationId)) {
        return res.status(400).json({
          error: "Invalid conversation ID."
        });
      }

      conversation = await conversations.findOne({
        _id: new ObjectId(conversationId),
        userId: req.userId
      });

      if (!conversation) {
        return res.status(404).json({
          error: "Conversation not found."
        });
      }
    } else {
      const created = {
        userId: req.userId,
        title: latest.content.slice(0, 60),
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const result = await conversations.insertOne(created);

      conversation = {
        ...created,
        _id: result.insertedId
      };
    }

    // Retrieve the user's approved memories.
    const savedMemories = await memories.find({
      userId: req.userId
    })
    .sort({ createdAt: -1 })
    .limit(30)
    .toArray();

    const memoryContext = savedMemories.length
      ? savedMemories.map(m => "- " + m.text).join("\n")
      : "No saved memories.";

    const instructions = `
You are JARVIS AI, a helpful personal AI assistant.

USER MEMORY:
${memoryContext}

CAPABILITIES:
- Natural language understanding.
- Programming and debugging assistance.
- HTML, CSS, JavaScript and other code generation.
- Project planning and technical explanations.

IMPORTANT:
- Treat memory as contextual information, not unquestionable truth.
- Never claim to have changed files or executed commands without tools.
- Ask for approval before destructive actions.
- Be honest about your capabilities.
- Never expose secrets or credentials.
- Provide complete, understandable code when requested.
`;

    const response = await ai.responses.create({
      model: process.env.OPENAI_MODEL || "gpt-4.1-mini",
      instructions,
      input: safeMessages.map(m => ({
        role: m.role,
        content: m.content
      }))
    });

    const reply = response.output_text;

    if (!reply || typeof reply !== "string") {
      throw new Error("AI returned an empty response.");
    }

    // Save only the latest user turn and its answer.
    const now = new Date();

    await messages.insertMany([
      {
        userId: req.userId,
        conversationId: conversation._id,
        role: "user",
        content: latest.content,
        createdAt: now
      },
      {
        userId: req.userId,
        conversationId: conversation._id,
        role: "assistant",
        content: reply,
        createdAt: new Date()
      }
    ]);

    await conversations.updateOne(
      {
        _id: conversation._id,
        userId: req.userId
      },
      {
        $set: { updatedAt: new Date() }
      }
    );

    res.json({
      success: true,
      reply,
      conversationId: conversation._id.toString()
    });

  } catch (error) {
    console.error("Chat error:", error.message);

    res.status(500).json({
      error: "JARVIS could not complete this request."
    });
  }
});

// ===================================
// ERROR HANDLING
// ===================================

app.use((err, req, res, next) => {
  console.error("Request error:", err.message);

  if (res.headersSent) return next(err);

  res.status(400).json({
    error: "Invalid request."
  });
});

// ===================================
// DATABASE STARTUP
// ===================================

async function start() {
  await client.connect();

  db = client.db(DB_NAME);

  users = db.collection("users");
  conversations = db.collection("conversations");
  messages = db.collection("messages");
  memories = db.collection("memories");

  await users.createIndex(
    { email: 1 },
    { unique: true }
  );

  await conversations.createIndex({
    userId: 1,
    updatedAt: -1
  });

  await messages.createIndex({
    userId: 1,
    conversationId: 1,
    createdAt: 1
  });

  await memories.createIndex({
    userId: 1,
    createdAt: -1
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.log("JARVIS backend running on port " + PORT);
    console.log("MongoDB Atlas connected.");
  });
}

start().catch(error => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});
