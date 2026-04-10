import { z } from "zod";

export const registerUserSchema = z
  .object({
    email: z.string().trim().pipe(z.email({ message: "Invalid email format" })),
    fullName: z.string().trim().min(1, "Full name is required"),
    phoneNumber: z
      .string()
      .trim()
      .min(7, "Phone number must be at least 7 characters long")
      .max(30, "Phone number must be at most 30 characters long")
      .optional(),
    password: z.string().min(8, "Password must be at least 8 characters long"),
    rePassword: z.string().min(1, "Please confirm your password"),
  })
  .refine((data) => data.password === data.rePassword, {
    message: "Passwords do not match",
    path: ["rePassword"],
  });

export const loginUserSchema = z.object({
  email: z.string().trim().pipe(z.email({ message: "Invalid email format" })),
  password: z.string().min(1, "Password is required"),
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, "Refresh token is required"),
});
