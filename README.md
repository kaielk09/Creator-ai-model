# PurpleCreator

PurpleCreator is a Node.js application for user accounts, Hugging Face OAuth, model project setup and chat UI.

## Local setup
1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env`.
3. Set `BASE_URL`, a random `SESSION_SECRET` (32+ characters), and `TOKEN_ENCRYPTION_KEY` (64 hexadecimal characters).
4. Run `npm install` and `npm start`.
5. Open the configured `BASE_URL`.

Generate secrets with Node:
- Session secret: `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`
- Encryption key: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`

## Hugging Face OAuth
The app serves OAuth CIMD metadata at `/.well-known/oauth-cimd` and uses Authorization Code + PKCE. The production callback URL is `/auth/huggingface/callback`. HTTPS is required in production. See the [official Hugging Face OAuth documentation](https://huggingface.co/docs/hub/oauth).

## Hosting
This is a Node.js app, not a GitHub Pages-only website. Deploy the repository to a Node.js host, set the start command to `npm start`, configure the environment variables, and ensure `DATA_DIR` is persistent and writable. GitHub Pages cannot run the backend. Point `purplecreator.pl` to the Node host only after that host provides its required DNS records.

## Accounts and data
- Email/password registration and login use bcrypt password hashing and SQLite sessions.
- Hugging Face access tokens are encrypted at rest using AES-256-GCM.
- SQLite files are stored in `DATA_DIR`; back them up.

## Model training
Training happens on the user's own computer. The generated script performs LoRA fine-tuning using a real Hugging Face dataset ID and pushes the adapter to the connected user's Hugging Face repository after local CLI login (`hf auth login`). Install packages from `training/requirements.txt`.

40,000 is the requested maximum starting sample count, not a promise that every dataset contains that many records or that every computer can train the selected base model. The script uses the smaller of the requested count and available dataset rows. Check dataset license, columns, model license, GPU VRAM and available disk space first. The current script uploads a LoRA adapter; a separate merge/deployment step is required before the model can be served as a standalone chat model.

## Current limitations
- The website login, registration, sessions, model configuration storage and HF OAuth flow are implemented in the code, but still need deployment and live testing with your domain.
- The Hugging Face OAuth scope used for account linking is `openid profile`. Uploading from the training computer uses its own `hf auth login` session.
- Chat UI and server route are implemented, but a linked OAuth token may not have Inference Providers permission. The trained LoRA adapter also needs to be merged and deployed before online chat will work. If Hugging Face returns a permission/model error, this is an integration limitation, not a successful response.
- API section is intentionally left empty.

Never commit `.env`, passwords, or access tokens. Use HTTPS and keep the database directory persistent.