import jwt from 'jsonwebtoken';
export const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];
    if (!token) {
        res.status(401).json({ message: 'Authentication required' });
        return;
    }
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
        if (err) {
            const message = err.name === 'TokenExpiredError'
                ? 'Session expired'
                : 'Invalid authentication token';
            res.status(403).json({ message });
            return;
        }
        // Type guard for JwtPayload
        if (!decoded ||
            typeof decoded !== 'object' ||
            !('id' in decoded) ||
            !('username' in decoded) ||
            !('role' in decoded)) {
            res.status(403).json({ message: 'Invalid token payload' });
            return;
        }
        const payload = decoded;
        req.user = {
            id: payload.id,
            username: payload.username,
            role: payload.role
        };
        next();
    });
};
