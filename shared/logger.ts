import { createLogger, format, transports } from 'winston';
import path from 'path';

const LOG_LEVEL = process.env.LOG_LEVEL ?? 'info';
const LOG_DIR = process.env.LOG_DIR ?? '/var/log/aegis';

export const logger = createLogger({
  level: LOG_LEVEL,
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.json(),
  ),
  transports: [
    new transports.Console({ format: format.combine(format.colorize(), format.simple()) }),
    new transports.File({ filename: path.join(LOG_DIR, 'aegis.log'), maxsize: 50 * 1024 * 1024, maxFiles: 5 }),
    new transports.File({ filename: path.join(LOG_DIR, 'error.log'), level: 'error' }),
  ],
});
