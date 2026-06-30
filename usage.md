# SecureKeystore — Usage & Deployment Guide

A complete walk-through of securing secrets, deploying them, and reading them at
runtime. CLI examples assume a global install (`npm install -g secure-keystore`);
otherwise replace `secure` with `node lib/cli.js`.

## Phase 1 — Initial setup (developer)

```bash
# 1. Create the plaintext keys file (first line MUST be the master key)
printf 'master:MySuperSecretMasterKey\n'  > keys.txt
printf 'api_key:sk_live_abc123\n'        >> keys.txt
printf 'jwt_secret:secret123\n'          >> keys.txt

# 2. Encrypt everything into a store named "production"
secure secure keys.txt MyUserKey123 production

# 3. Delete the plaintext file — it is no longer needed
rm keys.txt
```

The input file can also be a `.env` file (`master=...`, dotenv syntax with
comments/quotes/`export`) or a `.json` object (with a `"master"` property). The
format is picked from the file extension:

```bash
secure secure keys.env  MyUserKey123 production
secure secure keys.json MyUserKey123 production
```

What happens behind the scenes:

1. `keys.txt` is parsed into the master key plus key-value pairs.
2. A random salt is generated and the master key is encrypted with the user key
   (PBKDF2 + AES-256-GCM).
3. Each value gets its own random salt and a key derived from the master key,
   then is encrypted with AES-256-GCM and a fresh IV.
4. Everything is written to `.keystore/production/`.

## Phase 2 — Deployment to a server

```bash
# 1. Export the encrypted store into a portable bundle
secure export production ./production-backup.skb

# 2. Transfer it (scp, rsync, or your CI/CD artifact store)
scp production-backup.skb user@server:/app/backups/

# 3. Import it on the server
secure import /app/backups/production-backup.skb production

# 4. Verify
secure list production MyUserKey123
```

The bundle is already encrypted at rest, so interception alone does not expose
the secrets — they remain unreadable without the user key. For defense in depth
you can still encrypt the bundle again for transit (e.g. with `openssl`).

## Phase 3 — Runtime usage (application)

```javascript
// server.js
const SecureKeystore = require('secure-keystore');

const store = new SecureKeystore();
const userKey = process.env.USER_KEY; // never hardcode

// Decrypt only what you need, only when you need it
const apiKey = store.get('api_key', userKey, 'production');
const jwtSecret = store.get('jwt_secret', userKey, 'production');

app.use(jwt({ secret: jwtSecret }));
```

Values are decrypted on demand rather than all at once, and the encrypted files
never contain plaintext. (Note: once decrypted, a value is plaintext in process
memory for as long as your app holds it.)

## Common patterns

### Environment separation

```bash
secure secure dev-keys.txt     dev123      development
secure secure staging-keys.txt staging456  staging
secure secure prod-keys.txt    prod789     production
```

### Rotating / updating a single secret

```bash
secure set api_key new_value MyUserKey123 production
```

### Removing a secret

```bash
secure delete api_key production
```

### CI/CD deployment

```yaml
# .github/workflows/deploy.yml
- name: Deploy secrets
  run: |
    secure export production ./secrets.skb
    for server in ${{ env.SERVERS }}; do
      scp ./secrets.skb user@$server:/app/
      ssh user@$server "secure import /app/secrets.skb production"
    done
```

## Programmatic deployment

See [examples/deployment.js](examples/deployment.js) for a `KeystoreDeployer`
class that wraps export / import / transfer between keystore directories.

## Notes & caveats

- The `<user-key>` passed to `secure list` is not verified — listing only reads
  key names from metadata. `get`, `all`, and `set` are what actually require the
  correct user key.
- Backups are JSON bundles (`.skb`), not tar archives. They are portable across
  operating systems and require no external tools.
- The user key is the single root of trust: anyone who has it can decrypt the
  whole store. Treat it like a master password and never commit it.
