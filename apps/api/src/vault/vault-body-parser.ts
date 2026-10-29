import type {
  ErrorRequestHandler,
  Request,
  Response,
  NextFunction,
} from 'express';
import type { NestExpressApplication } from '@nestjs/platform-express';

export function configureVaultBodyParser(
  app: NestExpressApplication,
  authenticate: (request: Request) => Promise<void>,
) {
  const isVaultWrite = (request: { method?: string; url?: string }) =>
    request.method === 'PUT' && /^\/vault\/?(?:\?|$)/.test(request.url ?? '');
  // Verify the token before reading any large JSON body, not merely its header shape.
  app.use((request: Request, response: Response, next: NextFunction) => {
    if (!isVaultWrite(request)) {
      next();
      return;
    }
    void authenticate(request).then(
      () => next(),
      () => {
        response
          .status(401)
          .set('Cache-Control', 'no-store')
          .json({ message: 'Sign in required' });
      },
    );
  });
  // 20 MiB ciphertext envelope plus JSON request metadata. Reject compression.
  app.useBodyParser('json', {
    limit: 21 * 1024 * 1024,
    inflate: false,
    type: (request) =>
      isVaultWrite(request) &&
      /^application\/json(?:;|$)/i.test(request.headers['content-type'] ?? ''),
  });
  // Preserve the small default limit on unrelated API routes.
  app.useBodyParser('json', { limit: 100 * 1024, inflate: false });
  // Parser errors can carry the entire rejected body. Never pass them to logging.
  const rejectBody: ErrorRequestHandler = (
    error: unknown,
    _request,
    response,
    next,
  ) => {
    const type = (error as { type?: string } | null)?.type;
    if (typeof type !== 'string') {
      next(error);
      return;
    }
    const status =
      type === 'entity.too.large'
        ? 413
        : type === 'encoding.unsupported'
          ? 415
          : 400;
    response
      .status(status)
      .set('Cache-Control', 'no-store')
      .json({ message: 'Invalid or oversized request body' });
  };
  app.use(rejectBody);
}
