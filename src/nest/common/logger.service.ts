import { Injectable, LoggerService as NestLoggerService } from '@nestjs/common';

const DEBUG = process.env['DEBUG'] === '1';
const PREFIX = process.env['LOG_PREFIX'] || 'app';

@Injectable()
export class AppLoggerService implements NestLoggerService {
  private context?: string;

  constructor(context?: string) {
    this.context = context;
  }

  setContext(context: string) {
    this.context = context;
  }

  log(message: string, ...optionalParams: unknown[]) {
    if (optionalParams.length && typeof optionalParams[0] === 'object') {
      console.log(`[${PREFIX}]${this.context ? `[${this.context}]` : ''} ${message}`, optionalParams[0]);
    } else {
      console.log(`[${PREFIX}]${this.context ? `[${this.context}]` : ''} ${message}`, ...optionalParams);
    }
  }

  error(message: string, ...optionalParams: unknown[]) {
    if (optionalParams.length && typeof optionalParams[0] === 'object') {
      console.error(`[${PREFIX}]${this.context ? `[${this.context}]` : ''} ${message}`, optionalParams[0]);
    } else {
      console.error(`[${PREFIX}]${this.context ? `[${this.context}]` : ''} ${message}`, ...optionalParams);
    }
  }

  warn(message: string, ...optionalParams: unknown[]) {
    console.warn(`[${PREFIX}]${this.context ? `[${this.context}]` : ''} ${message}`, ...optionalParams);
  }

  debug(message: string, ...optionalParams: unknown[]) {
    if (!DEBUG) return;
    if (optionalParams.length && typeof optionalParams[0] === 'object') {
      console.log(`[${PREFIX}][DEBUG]${this.context ? `[${this.context}]` : ''} ${message}`, optionalParams[0]);
    } else {
      console.log(`[${PREFIX}][DEBUG]${this.context ? `[${this.context}]` : ''} ${message}`, ...optionalParams);
    }
  }

  verbose(message: string, ...optionalParams: unknown[]) {
    if (!DEBUG) return;
    console.log(`[${PREFIX}][VERBOSE]${this.context ? `[${this.context}]` : ''} ${message}`, ...optionalParams);
  }

  fatal(message: string, ...optionalParams: unknown[]) {
    console.error(`[${PREFIX}][FATAL]${this.context ? `[${this.context}]` : ''} ${message}`, ...optionalParams);
  }
}