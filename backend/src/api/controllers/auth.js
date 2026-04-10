import * as authService from "../../services/authService.js";

export async function registerUser(req, res) {
  const result = await authService.registerUser(req.body);

  res.status(201).json({
    message: "User registered successfully",
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    user: result.user,
  });
}

export async function loginUser(req, res) {
  const result = await authService.loginUser(req.body);

  res.status(200).json({
    message: "Login successful",
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    user: result.user,
  });
}

export function getCurrentUser(req, res) {
  res.status(200).json({
    user: req.user,
  });
}

export async function refreshAccessToken(req, res) {
  const result = await authService.refreshAccessToken(req.body);

  res.status(200).json({
    message: "Token refreshed successfully",
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    user: result.user,
  });
}

