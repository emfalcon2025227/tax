# Cloud Deployment Notes

## Locked production target

- Project: eng-cider-xghtt
- Region: europe-west2
- Service: tax-accounting-data-entry
- Runtime: Node.js 22
- Port: 3000

## Database

Supabase is the production database.

The deployment must use the existing production schema. Do not automatically run migration or seed SQL against the existing production database.

Verify the live schema before any additive migration.

## Secrets

Production secret values must come from a secure runtime secret mechanism such as Google Cloud Secret Manager.

Required when used:
- AUTH_SECRET_KEY
- SUPABASE_KEY
- GEMINI_API_KEY

Do not place secret values in source, Docker images, browser storage, API responses, or logs.

The current organization policy previously blocked Secret Manager usage in this project. Do not bypass that control by putting the values back into plaintext Cloud Run environment variables.

## Deployment

The repository includes cloudbuild.yaml for the Cloud Build to Artifact Registry to Cloud Run pipeline.

The Cloud Run service name and region in that file are fixed to the production target above.

## Verification

After deployment verify the actual active revision and run:
- /_health
- /api/health
- /api/status
- login
- /api/auth/me
- /api/suppliers
- /api/transactions

Use read-only production verification. Never create fake financial records for testing.
