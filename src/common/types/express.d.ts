declare namespace Express {
  export interface AuthUser {
    userId: string;
    email: string;
    organizationId?: string;
    sessionId?: string;
  }

  export interface Request {
    id: string;
    user?: AuthUser;
  }
}
