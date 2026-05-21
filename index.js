import express from 'express'
import { WebSocketServer, WebSocket } from 'ws'
import Database from 'better-sqlite3'
import fs from 'node:fs/promises'
import path from 'node:path'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const JWT_SECRET = 'brutalist_secret_key_123'

// Setup and verify SQLite Database Tables
const db = new Database('chat.db')
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT NOT NULL, 
        timestamp INTEGER NOT NULL, 
        content TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS dms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        content TEXT NOT NULL
    );
`)

const app = express()
app.use(express.json())

// Tracks live connections mapped to logged-in usernames
const activeClients = new Map()

// FIXED: Serves HTML asset file securely from the static/ directory path
app.get('/', async (req, res) => {
    try {
        const indexPath = path.join('static', 'index.html')
        const index = await fs.readFile(indexPath, 'utf8')
        res.setHeader('Content-Type', 'text/html')
        res.send(index)
    } catch (err) {
        res.status(500).send('Missing frontend structure. Ensure index.html is located inside your static/ folder.')
    }
})

// Secure Registration Endpoint
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' })
    
    try {
        const hash = await bcrypt.hash(password, 10)
        db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?);').run(username, hash)
        
        const token = jwt.sign({ username }, JWT_SECRET)
        res.json({ token, username })
    } catch (err) {
        res.status(400).json({ error: 'Username already taken' })
    }
})

// Secure Login Authentication Endpoint
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body
    const user = db.prepare('SELECT * FROM users WHERE username = ?;').get(username)
    
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return res.status(401).json({ error: 'Invalid credentials' })
    }
    
    const token = jwt.sign({ username }, JWT_SECRET)
    res.json({ token, username })
})

// Fetch Public Feed History
app.get('/history', (req, res) => {
    const pageIndex = parseInt(req.query.index ?? '0', 10)
    const offset = pageIndex * 10
    try {
        const messages = db.prepare('SELECT * FROM messages ORDER BY timestamp DESC LIMIT 10 OFFSET ?;').all(offset)
        res.json(messages.reverse()) 
    } catch (err) {
        res.status(500).json({ error: 'Database history error.' })
    }
})

// Fetch Private DM History Streams
app.get('/dm-history', (req, res) => {
    const authHeader = req.headers.authorization
    const target = req.query.target

    if (!authHeader || !target) return res.status(401).json({ error: 'Unauthorized payload context' })

    try {
        const token = authHeader.split(' ')[1] // Safely grab token text after Bearer string separator
        const decoded = jwt.verify(token, JWT_SECRET)
        const me = decoded.username

        const messages = db.prepare(`
            SELECT * FROM dms 
            WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
            ORDER BY timestamp DESC LIMIT 30;
        `).all(me, target, target, me)

        res.json(messages.reverse())
    } catch (err) {
        res.status(401).json({ error: 'Session expired' })
    }
})

app.listen(3000, () => console.log('HTTP operational on http://localhost:3000'))

// Socket Broadcasting Server Logic
const wss = new WebSocketServer({ port: 8080 })

wss.on('connection', (ws) => {
    let authenticatedUser = null

    ws.on('message', (msg) => {
        try {
            const data = JSON.parse(msg)

            if (data.type === 'auth') {
                const decoded = jwt.verify(data.token, JWT_SECRET)
                authenticatedUser = decoded.username
                activeClients.set(authenticatedUser, ws)
                return
            }

            if (!authenticatedUser) return;
            const timestamp = Date.now()

            // Handle Public Messaging Context
            if (data.type === 'public') {
                db.prepare('INSERT INTO messages (username, timestamp, content) VALUES (?, ?, ?);')
                    .run(authenticatedUser, timestamp, data.content)

                const payload = JSON.stringify({
                    type: 'public',
                    username: authenticatedUser,
                    timestamp,
                    content: data.content
                })

                wss.clients.forEach((client) => {
                    if (client.readyState === WebSocket.OPEN) client.send(payload)
                })
            }

            // Handle Private Direct Message Context
            if (data.type === 'dm') {
                db.prepare('INSERT INTO dms (sender, receiver, timestamp, content) VALUES (?, ?, ?, ?);')
                    .run(authenticatedUser, data.target, timestamp, data.content)

                const payload = JSON.stringify({
                    type: 'dm',
                    sender: authenticatedUser,
                    receiver: data.target,
                    timestamp,
                    content: data.content
                })

                ws.send(payload) // Render onto our user channel view instantly

                const targetSocket = activeClients.get(data.target)
                if (targetSocket && targetSocket.readyState === WebSocket.OPEN) {
                    targetSocket.send(payload)
                }
            }
        } catch (err) {
            console.error('Transmission fault parsing details:', err)
        }
    })

    ws.on('close', () => {
        if (authenticatedUser) activeClients.delete(authenticatedUser)
    })
})
