import type { ErrorRequestHandler } from 'express';
import type { NestExpressApplication } from '@nestjs/platform-express';

export function configureVaultBodyParser(app: NestExpressApplication) {
  // 20 MiB ciphertext envelope plus JSON request metadata. Reject compression.
  app.useBodyParser('json', {
    limit: 21 * 1024 * 1024,
    inflate: false,
    type: (request) =>
      request.method === 'PUT' &&
      /^\/vault\/?(?:\?|$)/.test(request.url ?? '') &&
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
