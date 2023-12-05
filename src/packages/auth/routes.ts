import type { Express } from 'express';
import rateLimit from 'express-rate-limit';
import { getEnv } from '../../env.js';
import { login, loginSSO, session, validateSSOToken } from './functions.js';

export default (app: Express) => {
  const { RATE_LIMITER_LOGIN_MAX } = getEnv();

  const loginLimiter = rateLimit({
    legacyHeaders: false,
    max: RATE_LIMITER_LOGIN_MAX,
    standardHeaders: true,
    windowMs: 15 * 60 * 1000, // 15 minutes
  });

  /**
   * @swagger
   * /auth/login:
   *   post:
   *     consumes:
   *       - application/json
   *     produces:
   *       - application/json
   *     requestBody:
   *       description: User's credentials
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               username:
   *                 type: string
   *               password:
   *                 type: string
   *     responses:
   *       200:
   *         description: AuthResponse
   *     summary: Login to initiate a session
   *     tags:
   *       - Auth
   */
  app.post('/auth/login', loginLimiter, async (req, res) => {
    const { body } = req;
    const { username, password } = body;
    const response = await login(username, password);
    res.json(response);
  });

  /**
   * @swagger
   * /auth/loginSSO:
   *   post:
   *     consumes:
   *       - application/json
   *     produces:
   *       - application/json
   *     requestBody:
   *       description: User's SSO token
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               ssoToken:
   *                 type: string
   *     responses:
   *       200:
   *         description: AuthResponse
   *     summary: Login to initiate a session
   *     tags:
   *       - Auth
   */
  app.post('/auth/loginSSO', loginLimiter, async (req, res) => {
    const { body } = req;
    const { ssoToken } = body;
    const { token, success, message } = await loginSSO(ssoToken);
    const resp = {
      token,
      success,
      message
    };
    res.json(resp);
  });

  /**
   * @swagger
   * /auth/validateSSO:
   *   post:
   *     consumes:
   *       - application/json
   *     produces:
   *       - application/json
   *     requestBody:
   *       description: User's SSO token
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               ssoToken:
   *                 type: string
   *     responses:
   *       200:
   *         description: AuthResponse
   *     summary: Validates a user's SSO token against external auth providers
   *     tags:
   *       - Auth
   */
  app.post('/auth/validateSSO', loginLimiter, async (req, res) => {
    const { body } = req;
    const { ssoToken } = body;
    const response = await validateSSOToken(ssoToken);
    res.json(response);
  });

  /**
   * @swagger
   * /auth/session:
   *   get:
   *     security:
   *       - bearerAuth: []
   *     produces:
   *       - application/json
   *     responses:
   *       200:
   *         description: SessionResponse
   *     summary: Checks if a session token is valid or invalid
   *     tags:
   *       - Auth
   */
  app.get('/auth/session', async (req, res) => {
    const authorizationHeader = req.get('authorization');
    const response = await session(authorizationHeader);
    res.json(response);
  });
};
