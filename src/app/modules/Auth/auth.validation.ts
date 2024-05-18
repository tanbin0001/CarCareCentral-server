import { z } from 'zod';

const loginValidationSchema = z.object({
  body: z.object({
    email: z.string({ required_error: 'Id is required.' }),
    password: z.string({ required_error: 'Password is required' }),
  }),
});

const refreshTokenValidationSchema = z.object({
  cookies: z.object({
    refreshToken: z.string({
      required_error: 'Refresh token is required!',
    }),
  }),
});

export const registerUserValidationSchema = z.object({
  body: z.object({
    name: z.string(),
    email: z.string().email(),
    password: z.string(),
    img: z.string().optional(), // Updated to match schema
  }),
});

export const AuthValidation = {
  loginValidationSchema,
  refreshTokenValidationSchema,
  registerUserValidationSchema
};
