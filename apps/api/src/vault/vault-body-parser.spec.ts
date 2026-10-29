import { ConfigService } from '@nestjs/config';
import { verifyToken } from '@clerk/backend';
import { ClerkAuthGuard } from '../auth/clerk-auth.guard';
import { Body, Controller, Put } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { gzipSync } from 'node:zlib';
import { configureVaultBodyParser } from './vault-body-parser';

jest.mock('@clerk/backend', () => ({ verifyToken: jest.fn() }));

@Controller('vault')
class BodyProbe {
  @Put()
  put(@Body() body: { ciphertext: string }) {
    return { length: body.ciphertext.length };
  }
}

describe('vault JSON transport bounds', () => {
  let app: NestExpressApplication;
  beforeAll(async () => {
    const module = await Test.createTestingModule({
      controllers: [BodyProbe],
    }).compile();
    app = module.createNestApplication<NestExpressApplication>();
    const auth = new ClerkAuthGuard(
      new ConfigService({
        CLERK_SECRET_KEY: 'fake-test-only-key',
        NODE_ENV: 'production',
        WEB_ORIGIN: 'https://test.example',
        AUTH_BYPASS_USER_ID: 'must-not-bypass-production',
      }),
    );
    jest.mocked(verifyToken).mockImplementation((token) => {
      if (token !== 'fixture-valid-token')
        throw new Error('Invalid fixture token');
      return Promise.resolve({ sub: 'fixture-user' } as Awaited<
        ReturnType<typeof verifyToken>
      >);
    });
    configureVaultBodyParser(app, async (request) => {
      expect(request.body).toBeUndefined();
      await auth.authenticateRequest(request);
    });
    await app.init();
  });
  afterAll(async () => {
    await app.close();
  });

  it('accepts a file-sized encrypted request through the real HTTP parser', async () => {
    await request(app.getHttpServer())
      .put('/vault')
      .set('Authorization', 'Bearer fixture-valid-token')
      .send({ ciphertext: 'a'.repeat(10 * 1024 * 1024) })
      .expect(200)
      .expect({ length: 10 * 1024 * 1024 });
  });
  it('rejects requests above the transport limit', async () => {
    await request(app.getHttpServer())
      .put('/vault')
      .set('Authorization', 'Bearer fixture-valid-token')
      .send({ ciphertext: 'a'.repeat(21 * 1024 * 1024) })
      .expect(413);
  });
  it('rejects compressed requests', async () => {
    await request(app.getHttpServer())
      .put('/vault')
      .set('Authorization', 'Bearer fixture-valid-token')
      .set('Content-Type', 'application/json')
      .set('Content-Encoding', 'gzip')
      .send(gzipSync(JSON.stringify({ ciphertext: 'opaque' })))
      .expect(415);
  });
  it('never echoes malformed request contents', async () => {
    const response = await request(app.getHttpServer())
      .put('/vault')
      .set('Authorization', 'Bearer fixture-valid-token')
      .set('Content-Type', 'application/json')
      .send('{"fake-secret-marker":')
      .expect(400);
    expect(JSON.stringify(response.body)).not.toContain('fake-secret-marker');
  });
  it('retains the small body limit on unrelated routes', async () => {
    await request(app.getHttpServer())
      .put('/unrelated')
      .send({ ciphertext: 'a'.repeat(101 * 1024) })
      .expect(413);
  });
  it.each(['', 'Bearer forged-token'])(
    'rejects unauthenticated JSON before parsing (%s)',
    async (authorization) => {
      await request(app.getHttpServer())
        .put('/vault')
        .set('Authorization', authorization)
        .set('Content-Type', 'application/json')
        .set('Content-Length', String(1024 * 1024))
        .send('{"invalid":')
        .expect(401);
    },
  );
  it('verifies the token with the configured authorized party', () => {
    expect(verifyToken).toHaveBeenCalledWith('fixture-valid-token', {
      secretKey: 'fake-test-only-key',
      authorizedParties: ['https://test.example'],
    });
  });
});
