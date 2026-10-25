import { EvidenceRedactor } from '../src/services/evidenceRedactor';

describe('Evidence Redaction Service Unit Tests', () => {
  test('Redacts Set-Cookie session token values from evidence', () => {
    const raw = 'Set-Cookie: session_token=sec_abc123456789xyz; Path=/; HttpOnly';
    const redacted = EvidenceRedactor.redact(raw);

    expect(redacted).not.toContain('sec_abc123456789xyz');
    expect(redacted).toContain('[REDACTED_COOKIE_VALUE]');
  });

  test('Redacts Authorization Bearer tokens', () => {
    const raw = 'Request header: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature';
    const redacted = EvidenceRedactor.redact(raw);

    expect(redacted).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    expect(redacted).toContain('[REDACTED_AUTH_TOKEN]');
  });

  test('Redacts database connection strings containing credentials', () => {
    const rawPg = 'Config leaked: postgresql://admin:SuperSecretPass123!@db.internal:5432/production';
    const redactedPg = EvidenceRedactor.redact(rawPg);

    expect(redactedPg).not.toContain('SuperSecretPass123!');
    expect(redactedPg).toContain('[REDACTED_DB_PASS]');

    const rawMongo = 'Config leaked: mongodb://db_admin:SecretMongoPass999!@cluster0.mongodb.net:27017/webshield_db?authSource=admin';
    const redactedMongo = EvidenceRedactor.redact(rawMongo);

    expect(redactedMongo).not.toContain('SecretMongoPass999!');
    expect(redactedMongo).toContain('[REDACTED_DB_PASS]');
  });

  test('Redacts AWS Access Key IDs', () => {
    const raw = 'AWS Key leaked: AKIAIOSFODNN7EXAMPLE in debug dump';
    const redacted = EvidenceRedactor.redact(raw);

    expect(redacted).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(redacted).toContain('[REDACTED_AWS_ACCESS_KEY]');
  });
});
