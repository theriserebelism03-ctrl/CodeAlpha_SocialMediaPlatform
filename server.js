const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'social-media-secret';
const dbPath = path.join(__dirname, 'social.db');
const db = new sqlite3.Database(dbPath);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const dbRun = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) {
        reject(err);
        return;
      }
      resolve({ id: this.lastID, changes: this.changes });
    });
  });

const dbGet = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(row);
    });
  });

const dbAll = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(rows);
    });
  });

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    req.user = decoded;
    next();
  });
}

async function initializeDatabase() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      likes INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
}

async function getFormattedPosts() {
  const posts = await dbAll(
    `
      SELECT
        p.id,
        p.content,
        p.likes,
        p.created_at,
        u.id AS author_id,
        u.username AS author_name
      FROM posts p
      JOIN users u ON u.id = p.user_id
      ORDER BY p.created_at DESC
    `
  );

  for (const post of posts) {
    const comments = await dbAll(
      `
        SELECT
          c.id,
          c.content,
          c.created_at,
          u.id AS author_id,
          u.username AS author_name
        FROM comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.post_id = ?
        ORDER BY c.created_at ASC
      `,
      [post.id]
    );

    post.comments = comments;
    post.author = {
      id: post.author_id,
      username: post.author_name,
    };
    delete post.author_id;
    delete post.author_name;
  }

  return posts;
}

app.get('/health', (req, res) => {
  res.json({ ok: true, status: 'running' });
});

app.post('/api/register', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    if (username.length < 3 || password.length < 6) {
      return res.status(400).json({
        error: 'Username must be at least 3 characters and password at least 6 characters',
      });
    }

    const existingUser = await dbGet('SELECT id FROM users WHERE username = ?', [username]);
    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await dbRun('INSERT INTO users (username, password_hash) VALUES (?, ?)', [
      username,
      passwordHash,
    ]);

    const user = { id: result.id, username };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '1d' });

    return res.status(201).json({ message: 'User registered successfully', token, user });
  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ error: 'Server error during registration' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const safeUser = { id: user.id, username: user.username };
    const token = jwt.sign(safeUser, JWT_SECRET, { expiresIn: '1d' });

    return res.json({ message: 'Login successful', token, user: safeUser });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Server error during login' });
  }
});

app.get('/api/posts', async (req, res) => {
  try {
    const posts = await getFormattedPosts();
    return res.json(posts);
  } catch (error) {
    console.error('Get posts error:', error);
    return res.status(500).json({ error: 'Unable to fetch posts' });
  }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const content = String(req.body.content || '').trim();

    if (!content) {
      return res.status(400).json({ error: 'Post content is required' });
    }

    const result = await dbRun('INSERT INTO posts (user_id, content, likes) VALUES (?, ?, 0)', [
      req.user.id,
      content,
    ]);

    const post = {
      id: result.id,
      content,
      likes: 0,
      created_at: new Date().toISOString(),
      author: {
        id: req.user.id,
        username: req.user.username,
      },
      comments: [],
    };

    return res.status(201).json(post);
  } catch (error) {
    console.error('Create post error:', error);
    return res.status(500).json({ error: 'Unable to create post' });
  }
});

app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
  try {
    const postId = Number(req.params.id);
    const content = String(req.body.content || '').trim();

    if (!Number.isInteger(postId) || postId <= 0) {
      return res.status(400).json({ error: 'Invalid post id' });
    }

    if (!content) {
      return res.status(400).json({ error: 'Comment content is required' });
    }

    const post = await dbGet('SELECT id FROM posts WHERE id = ?', [postId]);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const result = await dbRun('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)', [
      postId,
      req.user.id,
      content,
    ]);

    return res.status(201).json({
      id: result.id,
      post_id: postId,
      content,
      created_at: new Date().toISOString(),
      author: {
        id: req.user.id,
        username: req.user.username,
      },
    });
  } catch (error) {
    console.error('Create comment error:', error);
    return res.status(500).json({ error: 'Unable to add comment' });
  }
});

app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  try {
    const postId = Number(req.params.id);

    if (!Number.isInteger(postId) || postId <= 0) {
      return res.status(400).json({ error: 'Invalid post id' });
    }

    const post = await dbGet('SELECT id, likes FROM posts WHERE id = ?', [postId]);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const updated = await dbRun('UPDATE posts SET likes = likes + 1 WHERE id = ?', [postId]);
    const refreshedPost = await dbGet('SELECT likes FROM posts WHERE id = ?', [postId]);

    return res.json({
      success: true,
      id: postId,
      likes: refreshedPost.likes,
      changes: updated.changes,
    });
  } catch (error) {
    console.error('Like post error:', error);
    return res.status(500).json({ error: 'Unable to like post' });
  }
});

app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return next();
  }

  return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Social Media API running on http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  });

process.on('SIGINT', () => {
  db.close(() => {
    console.log('Database connection closed');
    process.exit(0);
  });
});
