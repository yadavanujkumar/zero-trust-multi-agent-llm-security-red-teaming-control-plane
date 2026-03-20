import Redis from 'ioredis';
import { logger } from './Logger';

export class RedisCache {
  private client: Redis;
  private readonly defaultTtlSeconds: number;

  constructor(
    redisUrl: string = 'redis://localhost:6379',
    defaultTtlSeconds: number = 300,
  ) {
    this.defaultTtlSeconds = defaultTtlSeconds;
    this.client = new Redis(redisUrl, {
      lazyConnect: true,
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
    });

    this.client.on('connect', () => logger.info('Redis connected'));
    this.client.on('error', (err: Error) =>
      logger.error('Redis error', { error: err.message }),
    );
  }

  async get<T>(key: string): Promise<T | null> {
    try {
      const value = await this.client.get(key);
      return value ? (JSON.parse(value) as T) : null;
    } catch (err) {
      logger.warn('Redis GET failed', { key, error: (err as Error).message });
      return null;
    }
  }

  async set(key: string, value: unknown, ttlSeconds?: number): Promise<void> {
    try {
      await this.client.set(
        key,
        JSON.stringify(value),
        'EX',
        ttlSeconds ?? this.defaultTtlSeconds,
      );
    } catch (err) {
      logger.warn('Redis SET failed', { key, error: (err as Error).message });
    }
  }

  async rpush(key: string, value: unknown): Promise<void> {
    try {
      await this.client.rpush(key, JSON.stringify(value));
      await this.client.expire(key, 60 * 60 * 24 * 7); // 7-day TTL for audit log
    } catch (err) {
      logger.warn('Redis RPUSH failed', { key, error: (err as Error).message });
    }
  }

  async disconnect(): Promise<void> {
    await this.client.quit();
  }

  isReady(): boolean {
    return this.client.status === 'ready';
  }
}
