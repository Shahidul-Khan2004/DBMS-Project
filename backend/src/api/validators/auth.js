import { registerUserSchema, loginUserSchema, refreshTokenSchema } from "./validationSchemas";
import validate from "./validator";

export const validateUserRegistration = validate(registerUserSchema);
export const validateUserLogin = validate(loginUserSchema);
export const validateRefreshToken = validate(refreshTokenSchema);