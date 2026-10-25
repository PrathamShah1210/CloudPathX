import { test, expect } from '@playwright/test';

const identity = {
  id: 'role-build',
  name: 'Build service role',
  type: 'service_role',
  account_id: '111111111111',
  risk_score: 85,
  policies: [{ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }],
};

async function setupV2Mock(page: any) {
  await page.route('**/api/v1/**', async (route: any) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace('/api/v1', '');
    const method = route.request().method();
    let data: any = { items: [], total: 0 };

    if (path === '/auth/login') {
      data = { token: 'test-session', user: { id: 'u1', email: 'analyst@example.test', role: 'Administrator' } };
    } else if (path === '/auth/me') {
      data = { id: 'u1', email: 'analyst@example.test', role: 'Administrator' };
    } else if (path === '/analytics') {
      data = {
        accounts: 1,
        identities: 3,
        non_human_identities: 2,
        high_risk_identities: 1,
        resources: 2,
        attack_paths: 1,
        critical_findings: 1,
        alerts: 2,
        scans: 1,
        trend: [{ date: '2026-10-25', score: 85 }],
      };
    } else if (path === '/identities') {
      data = { items: [identity], total: 1 };
    } else if (path === '/graph') {
      data = {
        nodes: [
          { id: identity.id, label: identity.name, type: identity.type },
          { id: 'bucket', label: 'Sensitive archive', type: 's3' },
        ],
        edges: [
          { id: 'e1', source: identity.id, target: 'bucket', type: 'MAY_ACCESS', confidence: 'potential' },
        ],
      };
    } else if (path === '/attack-paths') {
      data = {
        items: [
          {
            id: 'path-1',
            source: identity.id,
            target: 'bucket',
            narrative: 'Build service role escalates privileges to access Sensitive archive',
            cut_point: identity.id,
            risk_score: 85,
            nodes: [identity.id, 'bucket'],
          },
        ],
        total: 1,
      };
    } else if (path === '/iac/scan' && method === 'POST') {
      data = {
        gate_status: 'BLOCK',
        violations_count: 1,
        violations: [
          {
            rule_id: 'CPX-IAC-001',
            severity: 'CRITICAL',
            resource: 'aws_iam_policy.wildcard_policy',
            description: 'Wildcard Action (*) detected in IAM policy statement.',
          },
        ],
      };
    } else if (path === '/copilot/query' && method === 'POST') {
      data = {
        query: 'Which non-human identities have admin privileges?',
        answer: 'The service role `role-build` holds unrestricted wildcard administrative permissions across the account.',
        citations: ['IAM Deterministic Engine v2.0', 'Entity: role-build'],
        confidence: 'High (98%)',
        recommended_actions: ['Apply least-privilege scoping policy', 'Enable MFA restriction boundary'],
      };
    } else if (path === '/snapshots/compare' && method === 'POST') {
      data = {
        added_nodes_count: 1,
        removed_nodes_count: 0,
        net_risk_delta: 25,
        added_paths: [{ id: 'p-new', narrative: 'New attack vector via developer role' }],
        resolved_paths: [],
      };
    } else if (path === '/evaluation/results' || (path === '/evaluation/run' && method === 'POST')) {
      data = {
        metrics: {
          path_discovery_accuracy: 100.0,
          remediation_cut_point_precision: 96.8,
          detection_f1_score: 0.952,
          mean_traversal_latency_ms: 11.4,
        },
        scenarios: [
          { scenario: 'Lateral Movement via S3 Bucket Policy', expected: 1, detected: 1, precision: '100%', latency: '8.2ms' },
        ],
      };
    } else if (path === '/settings') {
      data = { scan_interval_minutes: 0, retention_days: 90, notifications_enabled: true };
    }

    await route.fulfill({ json: data });
  });

  await page.goto('/');
  await page.getByLabel('Email address').fill('analyst@example.test');
  await page.getByLabel('Password', { exact: true }).fill('not-a-real-password');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Security overview', exact: true })).toBeVisible();
}

test('theme toggle switches dark mode attribute', async ({ page }) => {
  await setupV2Mock(page);
  const toggle = page.getByRole('button', { name: 'Toggle theme' });
  await toggle.click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await toggle.click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
});

test('attack path explorer displays narrative and cut-point choke point', async ({ page }) => {
  await setupV2Mock(page);
  await page.getByRole('button', { name: 'Attack path explorer', exact: true }).click();
  await expect(page.getByText('Remediation Choke Point Identified')).toBeVisible();
  await expect(page.getByRole('heading', { name: /Build service role escalates/ })).toBeVisible();
});

test('iac security scanner runs scan and displays PR gate status', async ({ page }) => {
  await setupV2Mock(page);
  await page.getByRole('button', { name: 'IaC security scanner', exact: true }).click();
  await page.getByRole('button', { name: 'Scan Template for Violations' }).click();
  await expect(page.getByText('PR GATE STATUS: BLOCK')).toBeVisible();
  await expect(page.getByText('CPX-IAC-001')).toBeVisible();
});

test('security copilot responds with grounded citations', async ({ page }) => {
  await setupV2Mock(page);
  await page.getByRole('button', { name: 'Security Copilot', exact: true }).click();
  await page.getByRole('button', { name: 'Which non-human identities have admin privileges?' }).click();
  await expect(page.getByText('The service role `role-build` holds unrestricted')).toBeVisible();
  await expect(page.getByText('High (98%) Confidence')).toBeVisible();
});

test('time-travel graph computes snapshot diff', async ({ page }) => {
  await setupV2Mock(page);
  await page.getByRole('button', { name: 'Time-travel graph', exact: true }).click();
  await page.getByRole('button', { name: 'Compute Snapshot Diff' }).click();
  await expect(page.getByText('New Attack Paths Introduced')).toBeVisible();
});

test('research benchmark runs and displays academic metrics', async ({ page }) => {
  await setupV2Mock(page);
  await page.getByRole('button', { name: 'Research benchmark', exact: true }).click();
  await expect(page.locator('.metrics').getByText('100%')).toBeVisible();
  await expect(page.getByText('0.952')).toBeVisible();
});
