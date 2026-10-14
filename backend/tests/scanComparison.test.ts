describe('Scan Comparison & Finding Lifecycle Resolution Logic Tests', () => {
  const keyFor = (f: any) => `${f.rule_id || f.title}_${f.affected_url}`;

  test('Identifies resolved findings when vulnerability is absent in subsequent scan', () => {
    const baselineFindings = [
      { rule_id: 'SEC-HDR-CSP-MISSING', affected_url: 'http://localhost:8080', title: 'Missing CSP' },
      { rule_id: 'SEC-HDR-HSTS-MISSING', affected_url: 'http://localhost:8080', title: 'Missing HSTS' },
      { rule_id: 'SEC-EXP-ENV-LEAK', affected_url: 'http://localhost:8080/.env.example', title: 'Exposed Env' },
    ];

    // Current scan (after remediation): CSP and Env are fixed, but HSTS is still missing, and a new finding appeared
    const currentFindings = [
      { rule_id: 'SEC-HDR-HSTS-MISSING', affected_url: 'http://localhost:8080', title: 'Missing HSTS' },
      { rule_id: 'SEC-HDR-PERM-MISSING', affected_url: 'http://localhost:8080', title: 'Missing Permissions Policy' },
    ];

    const baseKeys = new Map(baselineFindings.map(f => [keyFor(f), f]));
    const currKeys = new Map(currentFindings.map(f => [keyFor(f), f]));

    const newFindings: any[] = [];
    const persistentFindings: any[] = [];
    const resolvedFindings: any[] = [];

    for (const [key, curr] of currKeys.entries()) {
      if (baseKeys.has(key)) {
        persistentFindings.push(curr);
      } else {
        newFindings.push(curr);
      }
    }

    for (const [key, base] of baseKeys.entries()) {
      if (!currKeys.has(key)) {
        resolvedFindings.push({ ...base, status: 'RESOLVED' });
      }
    }

    expect(resolvedFindings.length).toBe(2);
    expect(resolvedFindings.map(f => f.rule_id)).toEqual(['SEC-HDR-CSP-MISSING', 'SEC-EXP-ENV-LEAK']);

    expect(persistentFindings.length).toBe(1);
    expect(persistentFindings[0].rule_id).toBe('SEC-HDR-HSTS-MISSING');

    expect(newFindings.length).toBe(1);
    expect(newFindings[0].rule_id).toBe('SEC-HDR-PERM-MISSING');
  });
});
