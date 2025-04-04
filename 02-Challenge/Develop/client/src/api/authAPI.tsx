import { UserLogin } from "../interfaces/UserLogin";

const login = async (userInfo: UserLogin) => {
  try {
    const response = await fetch('http://localhost:3001/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'insomnia/2023.5.8' // Match server expectations
      },
      body: JSON.stringify({
        username: userInfo.username,
        password: userInfo.password
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || 'Login failed');
    }

    const data = await response.json();
    return data.token; // Returns JWT token for authentication
  } catch (error) {
    console.error('Login error:', error);
    throw error;
  }
}

export { login };