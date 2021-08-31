import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import initCamRoutes from './packages/cam/cam.js';
import initFileRoutes from './packages/files/files.js';
import initHealthRoutes from './packages/health/health.js';

function main(): void {
  const { PORT = '9000' } = process.env;
  const app = express();

  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors());
  app.use(express.json());

  initCamRoutes(app);
  initFileRoutes(app);
  initHealthRoutes(app);

  app.listen(PORT, () => {
    console.log(`🚀 AERIE-GATEWAY listening on ${PORT}`);
  });
}

main();
