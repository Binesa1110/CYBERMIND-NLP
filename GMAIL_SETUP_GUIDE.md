# Gmail security monitor setup

The Gmail feature is optional and disabled until you connect an account and
explicitly enable monitoring. This project currently implements a **single
local browser/account**, not a multi-user hosted service. Do not expose it to
the public internet as-is.

## What it reads and stores

- OAuth requests only `https://www.googleapis.com/auth/gmail.readonly`.
- When monitoring is enabled, new Inbox messages are analyzed by the existing
  `CyberMindAnalyzer`. The monitor also reconciles Gmail history periodically
  so delayed Pub/Sub notifications are not the only trigger.
- Message bodies are processed in memory and are not saved. Attachments are
  never downloaded or scanned.
- Sender, subject, received time, extracted URLs, attachment type/size, risk
  assessment, explanation, and limited keyword metadata are saved in SQLite.
- OAuth credentials are encrypted with `TOKEN_ENCRYPTION_KEY`; browser
  sessions are signed with `SESSION_SECRET_KEY`.
- The default SQLite file is under `%LOCALAPPDATA%\CYBERMIND\gmail-security`.
  Keep the encryption key safe: losing or changing it makes stored tokens
  unreadable.

## 1. Configure Google Cloud

1. Select or create a Google Cloud project.
2. Enable **Gmail API** and **Cloud Pub/Sub API**.
3. Configure the OAuth consent screen and add your Gmail address as a test
   user while the app is in testing mode.
4. Create an OAuth client ID of type **Web application**. Add this exact
   authorized redirect URI:

   ```text
   http://localhost:8000/gmail/callback
   ```

   Open the app as `http://localhost:8000/ui/`; switching between `localhost`
   and `127.0.0.1` breaks the browser-bound OAuth session.
5. Create a Pub/Sub topic and subscription. For example:

   ```powershell
   gcloud pubsub topics create cybermind-gmail --project YOUR_PROJECT_ID
   gcloud pubsub subscriptions create cybermind-gmail-pull `
     --topic cybermind-gmail --project YOUR_PROJECT_ID
   ```
6. Allow Gmail to publish notifications to the topic:

   ```powershell
   gcloud pubsub topics add-iam-policy-binding cybermind-gmail `
     --project YOUR_PROJECT_ID `
     --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" `
     --role="roles/pubsub.publisher"
   ```

Topic and subscription environment settings below are **IDs**, not full
`projects/...` resource names.

## 2. Create local secrets and environment file

From the project directory in PowerShell:

```powershell
Copy-Item .env.example .env
..\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
..\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
```

Edit `.env` and set:

```text
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/gmail/callback
SESSION_SECRET_KEY=paste-the-random-session-secret
TOKEN_ENCRYPTION_KEY=paste-the-generated-fernet-key
GOOGLE_CLOUD_PROJECT_ID=your-project-id
GMAIL_PUBSUB_TOPIC=cybermind-gmail
GMAIL_PUBSUB_SUBSCRIPTION=cybermind-gmail-pull
GMAIL_PUBSUB_MODE=pull
CYBERMIND_GMAIL_DEPLOYMENT=local
```

Leave push-only settings empty for pull mode. Never commit `.env` or paste
client secrets and generated keys into source code.

For pull mode, install and initialize the Google Cloud CLI, then authenticate
Application Default Credentials:

```powershell
gcloud auth application-default login
```

Grant the authenticated user or service account the Pub/Sub Subscriber role
for the subscription. For a user identity, for example:

```powershell
gcloud pubsub subscriptions add-iam-policy-binding cybermind-gmail-pull `
  --project YOUR_PROJECT_ID `
  --member="user:YOUR_GOOGLE_ACCOUNT" `
  --role="roles/pubsub.subscriber"
```

## 3. Start the API and worker

Open two terminals in the project directory:

```powershell
.\start.bat
```

In the second terminal:

```powershell
.\run_gmail_worker.bat
```

Keep both windows open. Open `http://localhost:8000/ui/`, select **Email
Monitor**, connect Gmail, review Google's requested read-only permission, and
then check the consent box before enabling monitoring. The worker starts
processing Inbox changes only after that explicit action.

## 4. Optional authenticated Pub/Sub push

Pull mode is recommended for local use. A push subscription must target an
HTTPS deployment reachable by Google and send an OIDC token for a dedicated
service account. Configure the subscription audience and the same values in
`.env`:

```text
GMAIL_PUBSUB_MODE=push
GMAIL_PUBSUB_PUSH_AUDIENCE=https://your-host.example/gmail/pubsub/push
GMAIL_PUBSUB_PUSH_SERVICE_ACCOUNT_EMAIL=pubsub-push@your-project.iam.gserviceaccount.com
```

The subscription endpoint is `/gmail/pubsub/push`. Grant the Pub/Sub service
agent permission to mint tokens for the push service account as required by
Google Cloud. Keep the worker process running to drain the durable local job
queue. This endpoint validates the OIDC audience, verified service-account
email, configured subscription, and Gmail notification payload.

Push mode does **not** make this local single-account application safe for
multi-user or public hosting. A production deployment needs a separate
multi-tenant identity model, shared durable storage, secure proxy settings,
operational monitoring, and a review of Google's OAuth verification
requirements.

## Troubleshooting and verification

- `redirect_uri_mismatch`: use `localhost` consistently and register the exact
  URI above in the OAuth client.
- OAuth setup is incomplete: check the listed missing variables at the Gmail
  dashboard. The app does not load secrets from `.env.example`; copy it to
  `.env` and fill the values.
- Pub/Sub watch fails: confirm Gmail API, Pub/Sub API, topic publisher IAM,
  project ID, topic ID, subscription ID, and worker credentials.
- History expiration is reconciled from the last successful sync. If the
  recovery exceeds its safety limit, monitoring reports an error instead of
  silently skipping the backlog.
- Pause monitoring in the dashboard before stopping the worker. Disconnecting
  removes saved alert metadata and attempts to revoke the Google token; if
  remote revocation fails, revoke CYBERMIND access in your Google Account.
- Automated tests use mocked Google API responses. They do not connect to a
  real Gmail account or prove that your Cloud project is configured.
