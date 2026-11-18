require('dotenv').config();

const crypto = require('node:crypto');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { prisma } = require('./db/config');

const app = express();
const port = Number(process.env.PORT) || 3000;
const saltRounds = 10;

app.use(express.json());

function createToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email },
        process.env.JWTSECRET,
        { jwtid: crypto.randomUUID(), expiresIn: '1h' }
    );
}

function requireAuth(req, res, next) {
    const authorization = req.get('Authorization');
    const [scheme, token, ...extra] = authorization?.trim().split(/\s+/) ?? [];

    if (scheme !== 'Bearer' || !token || extra.length > 0) {
        return res.status(401).json({ error: 'Missing or invalid authorization token' });
    }

    try {
        req.user = jwt.verify(token, process.env.JWTSECRET);
        return next();
    } catch (_error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

function normalizeEmail(email) {
    return email.trim().toLowerCase();
}

app.post('/signup', async (req, res, next) => {
    try {
        const { email, password, name } = req.body ?? {};

        if (typeof email !== 'string' || !email.trim()) {
            return res.status(400).json({ error: 'A valid email is required' });
        }
        if (typeof password !== 'string' || password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }
        if (name !== undefined && name !== null && typeof name !== 'string') {
            return res.status(400).json({ error: 'Name must be a string' });
        }

        const normalizedEmail = normalizeEmail(email);
        const existingUser = await prisma.user.findUnique({ where: { email: normalizedEmail } });
        if (existingUser) {
            return res.status(409).json({ error: 'Email is already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const user = await prisma.user.create({
            data: {
                email: normalizedEmail,
                password: hashedPassword,
                ...(name?.trim() ? { name: name.trim() } : {}),
            },
            select: { id: true, email: true, name: true, createdAt: true },
        });

        return res.status(201).json({ user, token: createToken(user) });
    } catch (error) {
        // The unique constraint also protects against two simultaneous signups.
        if (error?.code === 'P2002') {
            return res.status(409).json({ error: 'Email is already registered' });
        }
        return next(error);
    }
});

app.post('/login', async (req, res, next) => {
    try {
        const { email, password } = req.body ?? {};
        if (typeof email !== 'string' || !email.trim() || typeof password !== 'string' || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = await prisma.user.findUnique({ where: { email: normalizeEmail(email) } });
        const passwordMatches = user ? await bcrypt.compare(password, user.password) : false;
        if (!passwordMatches) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const basicUser = { id: user.id, email: user.email, name: user.name };
        return res.status(200).json({ user: basicUser, token: createToken(user) });
    } catch (error) {
        return next(error);
    }
});

app.get('/me', requireAuth, async (req, res, next) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user.id },
            select: { id: true, email: true, name: true, createdAt: true },
        });
        if (!user) return res.status(404).json({ error: 'User not found' });
        return res.status(200).json({ user });
    } catch (error) {
        return next(error);
    }
});

app.get('/dashboard', requireAuth, async (req, res, next) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user.id },
            select: { email: true, name: true },
        });
        if (!user) return res.status(404).json({ error: 'User not found' });
        const displayName = user.name?.trim() || user.email;
        return res.status(200).json({ message: `Welcome, ${displayName}!` });
    } catch (error) {
        return next(error);
    }
});

app.use((error, _req, res, _next) => {
    if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
        return res.status(400).json({ error: 'Request body must be valid JSON' });
    }
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
});

if (require.main === module) {
    app.listen(port, () => console.log(`Auth API listening on port ${port}`));
}

module.exports = { app, requireAuth, createToken };
