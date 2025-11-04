const axios = require('axios');
const jwt = require('jsonwebtoken');

exports.handler = async (event, context) => {
    const { code } = event.queryStringParameters;
    if (!code) { return { statusCode: 400, body: 'Missing GitHub code' }; }

    try {
        const CLIENT_ID = process.env.GITHUB_CLIENT_ID;
        const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
        const JWT_SECRET = process.env.JWT_SECRET;
        
        // 1. Обмен кода на Access Token GitHub
        const tokenResponse = await axios.post(
            'https://github.com/login/oauth/access_token',
            { client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code: code },
            { headers: { Accept: 'application/json' } }
        );
        const { access_token } = tokenResponse.data;

        // 2. Получение данных пользователя GitHub
        const userResponse = await axios.get('https://api.github.com/user', {
            headers: { Authorization: `token ${access_token}` }
        });
        const profile = userResponse.data;
        
        // 3. Генерация JWT-токена
        const payload = { id: profile.id, username: profile.login };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        // 4. Перенаправление на Frontend с токеном
        const FRONTEND_URL = 'https://fantastic-piroshki-8a73bc.netlify.app'; // Ваш Frontend Domain

        return {
            statusCode: 302,
            headers: {
                'Location': `${FRONTEND_URL}?token=${token}`,
            },
            body: ''
        };

    } catch (error) {
        return { statusCode: 500, body: 'Authentication failed' };
    }
};