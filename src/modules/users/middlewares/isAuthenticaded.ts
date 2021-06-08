import AppError from '@shared/errors/AppError';
import { verify } from 'jsonwebtoken';
import { NextFunction, request, Request, Response } from 'express';
import authConfig from '@config/auth';

export default function isAuthenticated(
    req: Request,
    res: Response,
    next: NextFunction,
): void {
    const authHeader = request.headers.authorization;

    if (!authHeader) {
        throw new AppError('JWT token is missing.');
    }

    const [, token] = authHeader.split(' ');

    try {
        const decodeToken = verify(token, authConfig.jwt.secret);

        return next();
    } catch {
        throw new AppError('invalid JWT token.');
    }
}
