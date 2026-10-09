# Storage acceptance tests

`make acceptance` builds the current checkout and runs a bounded CLI suite against an explicitly configured storage service. It requires live configuration and never falls back to fake storage. Ordinary `make test` runs the fake-storage regressions without requesting live credentials.

The suite creates one private bucket named `s5cmd-acceptance-<random hex>`. It checks multipart upload, download integrity, metadata, server-side copy, `pipe`, `sync --delete`, ListObjects v1/v2 pagination across 1,001 objects, and wildcard deletion. It uses at most eight fixture workers, two transfer workers, a 15-minute suite deadline, and two-minute command deadlines. Cleanup has a separate three-minute deadline and removes unfinished multipart uploads, object versions, delete markers, and the bucket. Cleanup failures fail the suite.

## Local configuration

Use a dedicated test organization and a restricted AWS profile. Supply actual configuration privately; do not commit it or copy it into PR descriptions.

| Variable | Meaning |
| --- | --- |
| `S5CMD_TEST_MODE` | `live` |
| `S5CMD_TEST_ENDPOINT_URL` | HTTPS storage origin |
| `S5CMD_REGION` | Storage region or availability zone |
| `S5CMD_IS_VIRTUAL_HOST` | `true` |
| `S5CMD_I_KNOW_WHAT_IM_DOING` | `1` to authorize disposable resources |
| `AWS_PROFILE` | Named profile used by fixtures and CLI commands |
| `AWS_CONFIG_FILE` | Private AWS configuration file |
| `AWS_SHARED_CREDENTIALS_FILE` | Private credentials file, empty for process credentials |
| `S5CMD_TEST_RESOURCE_FILE` | Optional new private file recording the exact bucket for recovery |

Unset static AWS credential variables and the legacy `S5CMD_ACCESS_KEY_ID` / `S5CMD_SECRET_ACCESS_KEY` variables. Use a renewable `credential_process` profile; local bootstrap credentials remain local. The fixture client uses the same protected process executor and credential-provider chain as the CLI. Storage TLS verification remains enabled. The suite passes region and endpoint explicitly and uses `--use-virtual-host-style` for custom endpoints.

Run:

```sh
make acceptance
```

The exact test selector is enforced in live mode, so a typo or a subset cannot produce a successful empty live run. Use fresh resource-ledger paths on reruns. The suite reports stage names and selected public error codes; it suppresses command output and raw credential/service diagnostics. Do not enable shell tracing, print environment variables, upload credential caches, or publish resource ledgers.

For a local MinIO rehearsal, retain the existing external-test configuration (`S5CMD_TEST_ENDPOINT_URL`, `S5CMD_REGION`, `S5CMD_IS_VIRTUAL_HOST=false`, both legacy test keys, and explicit consent) and run `go test ./e2e -run '^TestAcceptanceStorage$' -count=1 -timeout=20m` without selecting live mode. This uses synthetic local credentials and path-style addressing.

## GitHub OIDC process helper

`scripts/oidc_credentials.py` is a fallback for a protected GitHub Actions job when a reviewed renewable login action is unavailable. Install a pinned CWIC version supporting `cwic auth accesskey oidc`, then set `CWIC_API_URL`, `CWIC_CACHE_DIR`, and `S5CMD_TEST_ORG` from protected configuration. Use a fresh private cache directory and private AWS config/credentials files. Configure the selected profile with:

```ini
[profile acceptance]
credential_process = python3 /absolute/path/to/scripts/oidc_credentials.py
```

GitHub supplies `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` to the job. CWIC calls the helper's token mode on credential exchange and renewal; each token invocation requests a fresh GitHub JWT with audience `https://coreweave.com/iam`. JWTs go only to CWIC; storage credentials go only to the SDK. The helper suppresses CWIC stderr and returns a fixed error on failed login or renewal. It has no API-token fallback.

Run helper regressions with `python3 -m unittest discover -s scripts -p 'test_*.py'`. Normal PR CI runs these synthetic tests without OIDC permission or live configuration.

Storage federation must trust the actual subject issued for this repository's protected environment, including any subject customization. Grant the credential-exchange permission separately from storage permissions on the acceptance bucket prefix. Configure environment reviewers and release-PR verification before granting the execution job `id-token: write`; this harness PR does not enable privileged live workflows or publication. GitHub App authentication for release-bot event delivery is separate from storage federation.

## Cleanup and diagnosis

On ordinary failure, deadline expiry, or a termination signal, the live runner cancels commands and attempts scoped cleanup before exiting. Forced termination or loss of the runner can interrupt cleanup. Keep the private resource ledger available to the trusted cleanup step; recover only its exact bucket with fresh short-lived credentials. Never sweep all buckets or infer ownership from an account inventory. A ledger remains if cleanup fails and is removed on success.

A failed stage, authentication error, or cleanup error blocks the acceptance result. Check private endpoint/region configuration and WIF permissions first; inspect protected service-side diagnostics if needed. Do not expose JWTs, keys, signed requests, or raw HTTP responses in public Actions logs.

Credential renewal, failed renewal, provider precedence, helper sanitization, and retry behavior have synthetic regressions in `storage` and `e2e`; use those to inject failures without intentionally disrupting a live service. Local validation does not verify GitHub-issued subjects or protected-environment enforcement. Release workflow activation and its required gate must validate those separately.
