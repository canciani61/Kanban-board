import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  id: number;
  username: string;
  role: string;
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) {
    res.status(401).json({ message: 'Authentication required' });
    return;
  }

  jwt.verify(
    token,
    process.env.JWT_SECRET_KEY!,
    (err, decoded) => {
      if (err) {
        const message = err.name === 'TokenExpiredError' 
          ? 'Session expired' 
          : 'Invalid authentication token';
        res.status(403).json({ message });
        return;
      }

      // Type guard for JwtPayload
      if (
        !decoded || 
        typeof decoded !== 'object' ||
        !('id' in decoded) ||
        !('username' in decoded) ||
        !('role' in decoded)
      ) {
        res.status(403).json({ message: 'Invalid token payload' });
        return;
      }

      const payload = decoded as JwtPayload;
      req.user = {
        id: payload.id,
        username: payload.username,
        role: payload.role
      };
      
      next();
    }
  );
};