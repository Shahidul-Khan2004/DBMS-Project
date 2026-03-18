import express from 'express';
import {
  loginUser,
  refreshAccessToken,
  registerUser,
} from '../middlewares/auth.js';
import {
  validateLoginUser,
  validateRefreshToken,
  validateRegisterUser,
} from '../validators/auth.js';

const router = express.Router();

router.post('/register', validateRegisterUser, registerUser);
router.post('/login', validateLoginUser, loginUser);
router.post('/refresh', validateRefreshToken, refreshAccessToken);

export default router;
