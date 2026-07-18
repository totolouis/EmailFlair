import fs from 'fs';
import path from 'path';
import config from '../config';

class QuarantineService {
  storeRaw(emailId: string, rawBuffer: Buffer): string {
    const filePath = path.join(config.quarantineDir, `${emailId}.eml`);
    fs.writeFileSync(filePath, rawBuffer);
    return filePath;
  }

  readRaw(emlPath: string): Buffer | null {
    try {
      return fs.readFileSync(emlPath);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw err;
    }
  }

  deleteRaw(emlPath: string | null | undefined): void {
    if (emlPath && fs.existsSync(emlPath)) {
      try {
        fs.unlinkSync(emlPath);
      } catch (err) {
        console.error('[quarantine] error deleting file:', (err as Error).message);
      }
    }
  }
}

const quarantineService = new QuarantineService();
export { quarantineService, QuarantineService };
export default quarantineService;
