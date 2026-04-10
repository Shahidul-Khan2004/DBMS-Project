import express from 'express';
import {
  loginUser,
  refreshAccessToken,
  registerUser,
} from "../controllers/auth.js";
import {
  validateUserRegistration,
  validateUserLogin,
  validateRefreshToken,
} from '../validators/auth.js';

const router = express.Router();

router.post('/register', validateUserRegistration, registerUser);
router.post('/login', validateUserLogin, loginUser);
router.post('/refresh', validateRefreshToken, refreshAccessToken);

export default router;
