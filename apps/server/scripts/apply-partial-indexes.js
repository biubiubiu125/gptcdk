#!/usr/bin/env node
'use strict';

const { Client } = require('pg');

const STATEMENTS = [
  'CREATE UNIQUE INDEX IF NOT EXISTS "Account_team_active_email_key" ON "Account" (lower("email")) WHERE "stockKind" = \'team\' AND COALESCE("teamStatus", \'\') <> \'kicked\' AND "email" IS NOT NULL',
  'CREATE UNIQUE INDEX IF NOT EXISTS "TeamWorkspace_openaiWorkspaceId_key" ON "TeamWorkspace"("openaiWorkspaceId")',
];

async function main() {
  const url = process.env.DATABASE_URL || '';
  if (!/^postgres(ql)?:\/\//i.test(url)) {
    throw new Error('DATABASE_URL 必须是 PostgreSQL');
  }
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    for (const sql of STATEMENTS) await client.query(sql);
  } finally {
    await client.end();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

module.exports = { STATEMENTS };
