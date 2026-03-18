// import { z } from 'zod';

// const registerUserSchema = z
//   .object({
//     email: z.string().trim().pipe(z.email({ message: 'Invalid email format' })),
//     fullName: z.string().trim().min(1, 'Full name is required'),
//     password: z.string().min(8, 'Password must be at least 8 characters long'),
//     rePassword: z.string().min(1, 'Please confirm your password'),
//   })
//   .refine((data) => data.password === data.rePassword, {
//     message: 'Passwords do not match',
//     path: ['rePassword'],
//   });

// export function validateRegisterUser(req, res, next) {
//   const result = registerUserSchema.safeParse(req.body);

//   if (!result.success) {
//     return res.status(406).json({
//       error: 'Validation failed',
//       details: result.error.issues.map((issue) => ({
//         field: issue.path.join('.'),
//         message: issue.message,
//       })),
//     });
//   }

//   req.body = result.data;
//   next();
// }
