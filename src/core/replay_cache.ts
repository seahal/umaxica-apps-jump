import { JumpError } from './types';

export interface ReplayCache {
  checkAndStore(iss: string, jti: string, exp: number, now: number, skew: number): Promise<void>;
}

export class MemoryReplayCache implements ReplayCache {
  private readonly seen = new Map<string, number>();

  async checkAndStore(iss: string, jti: string, exp: number, now: number, skew: number) {
    const key = `replay:${iss}:${jti}`;
    this.gc(now);
    const existing = this.seen.get(key);
    if (existing && existing >= now) throw new JumpError('replay');
    this.seen.set(key, exp + skew);
  }

  private gc(now: number) {
    for (const [key, expiry] of this.seen) {
      if (expiry < now) this.seen.delete(key);
    }
  }
}

export class NoopReplayCache implements ReplayCache {
  async checkAndStore() {}
}
