import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getServiceInfo() {
    return {
      service: 'Vaultroom Keys API',
      status: 'ok',
      frontend: 'https://vaultroom-keys.vercel.app',
      health: '/health',
    };
  }

  getHealth() {
    return { status: 'ok' };
  }
}
