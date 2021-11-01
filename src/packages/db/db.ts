import type { Pool, PoolConfig } from 'pg';
import pg from 'pg';
import { getEnv } from '../../env.js';
import { initMerlin } from './merlin.js';
import { initUi } from './ui.js';

const { Pool: DbPool } = pg;

const {
  POSTGRES_DB: database,
  POSTGRES_HOST: host,
  POSTGRES_PASSWORD: password,
  POSTGRES_PORT: port,
  POSTGRES_USER: user,
} = getEnv();

export class Db {
  private static pool: Pool | null = null;

  /**
   * @note Assumes init() has already been called and completed.
   * This is so we do not need to make this function async.
   */
  static getDb(): Pool {
    return Db.pool as Pool;
  }

  static async init(): Promise<void> {
    try {
      const poolConfig: PoolConfig = {
        database,
        host,
        password,
        port: parseInt(port, 10),
        user,
      };

      Db.pool = new DbPool(poolConfig);
      await Db.createSchemas();
      await initMerlin(Db.pool);
      await initUi(Db.pool);
    } catch (error) {
      const { message } = error as Error;
      console.log(message);
    }
  }

  static async createSchemas(): Promise<void> {
    try {
      if (Db.pool) {
        await Db.pool.query(`
          create schema if not exists merlin
          authorization ${user};
        `);
        await Db.pool.query(`
          create schema if not exists ui
          authorization ${user};
        `);
      } else {
        console.error('Error: Cannot create schemas. No database pool exists.');
      }
    } catch (error) {
      const { message } = error as Error;
      console.log(message);
    }
  }
}
