import databaseService from '../services/DatabaseService';
import { IEmail, IEmailCreate, EmailStatus } from '../interfaces';

interface EmailQueryParams {
  tenantId: string;
  status?: string;
  domain?: string;
  limit?: number;
}

class EmailRepository {
  findAll(params: EmailQueryParams): IEmail[] {
    const { tenantId, status, domain, limit = 100 } = params;
    let query = 'SELECT * FROM emails WHERE tenant_id = ?';
    const queryParams: unknown[] = [tenantId];

    if (status) {
      query += ' AND status = ?';
      queryParams.push(status);
    }
    if (domain) {
      query += ' AND domain = ?';
      queryParams.push(domain);
    }
    query += ' ORDER BY received_at DESC LIMIT ?';
    queryParams.push(limit);

    return databaseService.getDb().prepare(query).all(...queryParams) as IEmail[];
  }

  findById(tenantId: string, id: string): IEmail | null {
    const row = databaseService
      .getDb()
      .prepare('SELECT * FROM emails WHERE tenant_id = ? AND id = ?')
      .get(tenantId, id) as IEmail | undefined;

    return row || null;
  }

  create(email: IEmailCreate): void {
    databaseService
      .getDb()
      .prepare(
        `INSERT INTO emails (
          id, tenant_id, domain, sender, recipient, subject, remote_ip,
          spam_score, decision, status, relay_id, reason, headers_json,
          size_bytes, eml_path, received_at, processed_at
        ) VALUES (
          @id, @tenant_id, @domain, @sender, @recipient, @subject, @remote_ip,
          @spam_score, @decision, @status, @relay_id, @reason, @headers_json,
          @size_bytes, @eml_path, @received_at, @processed_at
        )`
      )
      .run(email);
  }

  updateStatus(id: string, status: EmailStatus, decision: string, processedAt: string): void {
    databaseService
      .getDb()
      .prepare('UPDATE emails SET status = ?, decision = ?, processed_at = ? WHERE id = ?')
      .run(status, decision, processedAt, id);
  }

  delete(id: string): void {
    databaseService.getDb().prepare('DELETE FROM emails WHERE id = ?').run(id);
  }

  getStatusSummary(tenantId: string): Record<string, number> {
    const rows = databaseService
      .getDb()
      .prepare('SELECT status, COUNT(*) as count FROM emails WHERE tenant_id = ? GROUP BY status')
      .all(tenantId) as { status: string; count: number }[];

    const totals: Record<string, number> = { RECEIVED: 0, FORWARDED: 0, QUARANTINED: 0, REJECTED: 0 };
    rows.forEach((r) => {
      totals[r.status] = r.count;
    });
    return totals;
  }
}

const emailRepository = new EmailRepository();
export { emailRepository, EmailRepository };
export default emailRepository;
