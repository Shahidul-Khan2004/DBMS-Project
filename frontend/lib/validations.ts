import { z } from "zod";

export const registerSchema = z
  .object({
    email: z
      .string()
      .trim()
      .pipe(z.email({ message: "Invalid email format" })),
    fullName: z.string().trim().min(1, "Full name is required"),
    phoneNumber: z
      .string()
      .trim()
      .regex(/^\d{11}$/, "Phone number must be exactly 11 digits"),
    password: z.string().min(8, "Password must be at least 8 characters long"),
    rePassword: z.string().min(1, "Please confirm your password"),
  })
  .refine((data) => data.password === data.rePassword, {
    message: "Passwords do not match",
    path: ["rePassword"],
  });

export type RegisterInput = z.infer<typeof registerSchema>;

export const loginSchema = z.object({
  email: z
    .string()
    .trim()
    .pipe(z.email({ message: "Invalid email format" })),
  password: z.string().min(1, "Password is required"),
});

export type LoginInput = z.infer<typeof loginSchema>;

