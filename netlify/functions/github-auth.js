// github-auth.js

const jwt = require('jsonwebtoken'); // <-- ЭТО КРИТИЧНО! ДОБАВИТЬ!

exports.handler = async (event, context) => {
    // Получаем CLIENT_ID из переменных окружения Netlify
    const CLIENT_ID = process.env.GITHUB_CLIENT_ID; 

    // Формируем URL для возврата 
    const REDIRECT_URI = 'https://fantastic-piroshki-8a73bc.netlify.app/.netlify/functions/github-callback';

    const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=user:email`;

    // Перенаправление пользователя на GitHub
    return {
        statusCode: 302,
        headers: {
            'Location': githubAuthUrl,
        },
        body: ''
    };
};