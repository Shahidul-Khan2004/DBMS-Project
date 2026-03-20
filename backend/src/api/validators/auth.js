import { registerUserSchema, loginUserSchema, refreshTokenSchema } from "./validationSchemas.js";
import validate from "./validator.js";

export const validateUserRegistration = validate("registration", registerUserSchema);
export const validateUserLogin = validate("login", loginUserSchema);
export const validateRefreshToken = validate("refresh token", refreshTokenSchema);