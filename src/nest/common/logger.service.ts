import { Injectable, LoggerService as NestLoggerService } from '@nestjs/common';

const DEBUG = process.env['DEBUG'] === '1';
const PREFIX = process.env['LOG_PREFIX'] || 'app';

@Injectable()
export class AppLoggerService implements NestLoggerService {
  private context: string = '';

  setContext(context: string) {
    this.context = context;
  }

  private prefix(): string {
    return this.context ? `[${this.context}]` : '';
  }

  log(message: string, ...optionalParams: unknown[]) {
    if (optionalParams.length && typeof optionalParams[0] === 'object') {
      console.log(`[${PREFIX}]${this.prefix()} ${message}`, optionalParams[0]);
    } else {
      console.log(`[${PREFIX}]${this.prefix()} ${message}`, ...optionalParams);
    }
  }

  error(message: string, ...optionalParams: unknown[]) {
    if (optionalParams.length && typeof optionalParams[0] === 'object') {
      console.error(`[${PREFIX}]${this.prefix()} ${message}`, optionalParams[0]);
    } else {
      console.error(`[${PREFIX}]${this.prefix()} ${message}`, ...optionalParams);
    }
  }

  warn(message: string, ...optionalParams: unknown[]) {
    console.warn(`[${PREFIX}]${this.prefix()} ${message}`, ...optionalParams);
  }

  debug(message: string, ...optionalParams: unknown[]) {
    if (!DEBUG) return;
    if (optionalParams.length && typeof optionalParams[0] === 'object') {
      console.log(`[${PREFIX}][DEBUG]${this.prefix()} ${message}`, optionalParams[0]);
    } else {
      console.log(`[${PREFIX}][DEBUG]${this.prefix()} ${message}`, ...optionalParams);
    }
  }

  verbose(message: string, ...optionalParams: unknown[]) {
    if (!DEBUG) return;
    console.log(`[${PREFIX}][VERBOSE]${this.prefix()} ${message}`, ...optionalParams);
  }

  fatal(message: string, ...optionalParams: unknown[]) {
    console.error(`[${PREFIX}][FATAL]${this.prefix()} ${message}`, ...optionalParams);
  }
}