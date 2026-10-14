import Redis from 'ioredis';
import dotenv from 'dotenv';

dotenv.config();

const redisUrl = process.env.REDIS_URL || 'redis://127.0.0.1:6379';

// In-Memory Storage Fallback when Redis is not running
const inMemoryStore: Record<string, string> = {};

let isRedisConnected = false;

export const redisClient = new Redis(redisUrl, {
  maxRetriesPerRequest: null,
  enableReadyCheck: false,
  lazyConnect: true,
  retryStrategy: () => null, // Do not spam retries if Redis is down
});

// Suppress unhandled error crash when Redis is offline in local dev
redisClient.on('error', () => {
  isRedisConnected = false;
});

redisClient.connect().then(() => {
  isRedisConnected = true;
  console.log('[Redis] Connected to Redis server');
}).catch(() => {
  isRedisConnected = false;
  console.log('[Redis] Redis unavailable. Using In-Memory Key-Value Fallback for local execution.');
});

export const redisStore = {
  async setex(key: string, seconds: number, value: string): Promise<void> {
    if (isRedisConnected) {
      try {
        await redisClient.setex(key, seconds, value);
        return;
      } catch (e) {
        isRedisConnected = false;
      }
    }
    inMemoryStore[key] = value;
  },

  async get(key: string): Promise<string | null> {
    if (isRedisConnected) {
      try {
        return await redisClient.get(key);
      } catch (e) {
        isRedisConnected = false;
      }
    }
    return inMemoryStore[key] || null;
  }
};
