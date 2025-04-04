import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// Add interface for authenticated request
declare global {
  namespace Express {
    interface Request {
      user?: { 
        id: number;
        username: string;
        role: string;
      };
    }
  }
}

export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      res.status(400).json({ message: 'Username and password are required' });
      return;
    }

    const user = await User.findOne({ 
      where: { username: username.toLowerCase() } 
    });

    if (!user) {
      res.status(401).json({ message: 'Invalid credentials' });
      return;
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      res.status(401).json({ message: 'Invalid credentials' });
      return;
    }

    // Type assertion for user role
    const userWithRole = user as unknown as { 
      id: number;
      username: string;
      password: string;
      role: string;
    };

    const token = jwt.sign(
      { 
        id: userWithRole.id,
        username: userWithRole.username,
        role: userWithRole.role 
      }, 
      process.env.JWT_SECRET_KEY!,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      user: {
        id: userWithRole.id,
        username: userWithRole.username,
        role: userWithRole.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const router = Router();
router.post('/login', login);
export default router;