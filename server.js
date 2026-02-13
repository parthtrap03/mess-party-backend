import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';

import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security Configurations
app.set('trust proxy', 1); // Trust first proxy (important for Vercel/Cloud)
app.use(helmet()); // Secure HTTP Headers

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 500, // Limit each IP to 500 requests per windowMs
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: { error: 'Too many requests, please try again later.' },
    // Skip rate limiting for the polling endpoint (called every few seconds)
    skip: (req) => req.path === '/api/party/status'
});
app.use(limiter); // Apply rate limiting to all requests (except polling)

// Configurations
const ADMIN_PASSKEY = process.env.ADMIN_PASSKEY || 'admin123';
const PARTY_PASSKEY = process.env.PARTY_PASSKEY || 'welcome';
const REQUIRED_GUESTS = parseInt(process.env.REQUIRED_GUESTS) || 4; // Reverted to 4 (Total 5)
const MAX_REQUESTS = 10;

// In-memory storage
let requestCount = 0;

// Party mode storage
let partyState = {
    adminSession: null,      // Token for the host/admin
    guestSessions: new Set(), // Set of tokens for guests
    limitReached: false      // Sticky flag: true once we hit 5 users
};

app.use(cors());
app.use(express.json());

// Party: Authenticate user and determine role
app.post('/api/party/authenticate', (req, res) => {
    const { passkey } = req.body;
    const clientToken = req.headers['x-session-token'];

    if (passkey !== PARTY_PASSKEY) {
        return res.status(401).json({ error: 'Invalid passkey' });
    }

    // Response helper
    const getStatus = (role, token, message) => {
        const isLimitReached = partyState.limitReached || partyState.guestSessions.size >= REQUIRED_GUESTS;
        return {
            role,
            token,
            guestCount: isLimitReached ? REQUIRED_GUESTS : partyState.guestSessions.size,
            requiredGuests: REQUIRED_GUESTS,
            totalUsers: isLimitReached ? (REQUIRED_GUESTS + 1) : (partyState.guestSessions.size + (partyState.adminSession ? 1 : 0)),
            maxUsers: REQUIRED_GUESTS + 1,
            // Admin gets secret access if limit matches OR limit was reached previously
            limitReached: isLimitReached,
            isFull: isLimitReached,
            message
        };
    };

    // 1. Check if user is already authenticated with a valid token
    if (clientToken) {
        if (partyState.adminSession === clientToken) {
            return res.json(getStatus('host', clientToken, 'Welcome back, Admin'));
        }
        // If limit is reached, Guests are invalid (logged out)
        if (!partyState.limitReached && partyState.guestSessions.has(clientToken)) {
            return res.json(getStatus('guest', clientToken, 'Welcome back, Guest'));
        }
    }

    // 2. Assign new roles
    const newToken = crypto.randomUUID();

    // First user becomes Admin
    if (!partyState.adminSession) {
        partyState.adminSession = newToken;
        return res.json(getStatus('host', newToken, 'You are the Admin'));
    }

    // If limit reached, no new guests allowed
    if (partyState.limitReached) {
        return res.status(403).json({
            error: 'Party is Over',
            limitReached: true,
            isFull: true,
            role: 'guest',
            totalUsers: REQUIRED_GUESTS + 1,
            maxUsers: REQUIRED_GUESTS + 1,
            guestCount: REQUIRED_GUESTS,
            requiredGuests: REQUIRED_GUESTS,
            partyOver: true,
            message: 'Thank you for joining! The party is complete.'
        });
    }

    // Next 4 users become Guests
    if (partyState.guestSessions.size < REQUIRED_GUESTS) {
        partyState.guestSessions.add(newToken);

        // Check if this was the LAST guest needed
        if (partyState.guestSessions.size >= REQUIRED_GUESTS) {
            partyState.limitReached = true;

            // OPTIONAL: Clear guests immediately or keep them?
            // User requested: "guests should automatically logout"
            // We'll clear the set so their next poll fails/resets.
            partyState.guestSessions.clear();
        }

        return res.json(getStatus('guest', newToken, 'You are a Guest'));
    }

    // Fallback (should be covered by limitReached check above, but for safety)
    return res.status(403).json({
        error: 'Party Full',
        limitReached: true,
        guestCount: partyState.guestSessions.size,
        requiredGuests: REQUIRED_GUESTS,
        totalUsers: partyState.guestSessions.size + (partyState.adminSession ? 1 : 0),
        maxUsers: REQUIRED_GUESTS + 1
    });
});

// Party: Get current status
app.get('/api/party/status', (req, res) => {
    const clientToken = req.headers['x-session-token'];
    const isLimitReached = partyState.limitReached || partyState.guestSessions.size >= REQUIRED_GUESTS;

    // Check if the client's session is still valid
    let sessionValid = false;
    if (clientToken) {
        sessionValid = partyState.adminSession === clientToken || partyState.guestSessions.has(clientToken);
    }

    res.json({
        guestCount: isLimitReached ? REQUIRED_GUESTS : partyState.guestSessions.size,
        requiredGuests: REQUIRED_GUESTS,
        totalUsers: isLimitReached ? (REQUIRED_GUESTS + 1) : (partyState.guestSessions.size + (partyState.adminSession ? 1 : 0)),
        maxUsers: REQUIRED_GUESTS + 1,
        limitReached: partyState.limitReached,
        sessionValid: sessionValid
    });
});

// Party: Debug endpoint (check admin status)
app.get('/api/party/debug', (req, res) => {
    res.json({
        hasAdmin: !!partyState.adminSession,
        adminToken: partyState.adminSession ? partyState.adminSession.substring(0, 8) + '...' : null,
        guestCount: partyState.guestSessions.size,
        limitReached: partyState.limitReached,
        totalUsers: partyState.guestSessions.size + (partyState.adminSession ? 1 : 0)
    });
});

// Party: Reset party state (admin only)
app.post('/api/party/reset', (req, res) => {
    const passkey = req.headers['x-passkey'];
    if (passkey !== ADMIN_PASSKEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    partyState = {
        adminSession: null,
        guestSessions: new Set(),
        limitReached: false
    };

    res.json({
        success: true,
        message: 'Party state reset'
    });
});

// Party: Logout (resets party if admin logs out)
app.post('/api/party/logout', (req, res) => {
    const clientToken = req.headers['x-session-token'];

    // Check if this is the admin logging out
    if (clientToken && partyState.adminSession === clientToken) {
        // Reset the entire party state
        partyState = {
            adminSession: null,
            guestSessions: new Set(),
            limitReached: false
        };

        return res.json({
            success: true,
            message: 'Admin logged out, party reset'
        });
    }

    // If it's a guest, just acknowledge
    if (clientToken && partyState.guestSessions.has(clientToken)) {
        partyState.guestSessions.delete(clientToken);
        return res.json({
            success: true,
            message: 'Guest logged out'
        });
    }

    res.json({ success: true, message: 'Logged out' });
});

// Public: Track a new request
app.post('/api/track-request', (req, res) => {
    if (requestCount >= MAX_REQUESTS) {
        return res.status(429).json({
            error: 'Request limit reached',
            currentCount: requestCount,
            remainingRequests: 0,
            limitReached: true
        });
    }

    requestCount++;
    res.json({
        success: true,
        currentCount: requestCount,
        remainingRequests: MAX_REQUESTS - requestCount
    });
});

// Public: Get current count
app.get('/api/request-count', (req, res) => {
    res.json({
        currentCount: requestCount,
        maxRequests: MAX_REQUESTS,
        remainingRequests: Math.max(0, MAX_REQUESTS - requestCount),
        limitReached: requestCount >= MAX_REQUESTS
    });
});

// Admin: Middleare for passkey verification
const verifyPasskey = (req, res, next) => {
    const passkey = req.headers['x-passkey'];
    if (passkey !== ADMIN_PASSKEY) {
        return res.status(401).json({ error: 'Unauthorized: Invalid passkey' });
    }
    next();
};

// Admin: Get statistics
app.get('/api/admin/stats', verifyPasskey, (req, res) => {
    res.json({
        currentCount: requestCount,
        maxRequests: MAX_REQUESTS,
        remainingRequests: Math.max(0, MAX_REQUESTS - requestCount),
        limitReached: requestCount >= MAX_REQUESTS
    });
});

// Admin: Reset count
app.post('/api/admin/reset', verifyPasskey, (req, res) => {
    requestCount = 0;
    res.json({
        success: true,
        message: 'Request count reset',
        currentCount: 0
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Admin passkey is: ${ADMIN_PASSKEY}`);
    console.log(`Party passkey is: ${PARTY_PASSKEY}`);
    console.log(`Required guests: ${REQUIRED_GUESTS}`);
});

