import { Body, Controller, Put } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { gzipSync } from 'node:zlib';
import { configureVaultBodyParser } from './vault-body-parser';

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
    configureVaultBodyParser(app);
    await app.init();
  });
  afterAll(async () => {
    await app.close();
  });

  it('accepts a file-sized encrypted request through the real HTTP parser', async () => {
    await request(app.getHttpServer())
      .put('/vault')
      .send({ ciphertext: 'a'.repeat(10 * 1024 * 1024) })
      .expect(200)
      .expect({ length: 10 * 1024 * 1024 });
  });
  it('rejects requests above the transport limit', async () => {
    await request(app.getHttpServer())
      .put('/vault')
      .send({ ciphertext: 'a'.repeat(21 * 1024 * 1024) })
      .expect(413);
  });
  it('rejects compressed requests', async () => {
    await request(app.getHttpServer())
      .put('/vault')
      .set('Content-Type', 'application/json')
      .set('Content-Encoding', 'gzip')
      .send(gzipSync(JSON.stringify({ ciphertext: 'opaque' })))
      .expect(415);
  });
  it('never echoes malformed request contents', async () => {
    const response = await request(app.getHttpServer())
      .put('/vault')
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
});
