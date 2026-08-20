# Usage and deployment

Securing secrets, getting them onto a server, and reading them at run time.

CLI examples assume a global install (`npm install -g @tech-style/secure-keystore`);
otherwise use `npx secure-keystore …`, or `node bin/cli.js …` from a clone.

---

## Phase 1 — On the developer machine

```bash
# 1. Write the plaintext keys file
cat > keys.env <<'KEYS'
master=MySuperSecretMasterKey
api_key=sk_live_abc123
jwt_secret=eyJhbGciOiJIUzI1NiJ9
db_url=postgres://user:pass@localhost:5432/app
KEYS

# 2. Encrypt it into a store called "production"
secure-keystore secure keys.env "$USER_KEY" production

# 3. Delete the plaintext. It has served its purpose.
rm keys.env
```

The input format follows the extension — `.env` above, or `.txt` colon format,
or a flat `.json` object. Each needs a `master` entry. See
[SPEC.md §7](../SPEC.md#7-input-files).

What happens: the master key is encrypted under a key derived from your user
key, each value is encrypted under its own key derived from the master key, and
all of it lands in `.keystore/production/`.

**Choosing a user key.** It is the only secret, so make it one:

```bash
export USER_KEY=$(openssl rand -base64 32)
```

Never hardcode it, never commit it, and keep it out of the same channel the
store travels through.

---

## Phase 2 — Getting it onto a server

```bash
# 1. Export the store as one portable bundle
secure-keystore export production ./production.skb

# 2. Move it — scp, rsync, a CI artifact, a container layer
scp production.skb deploy@server:/app/

# 3. Import it there
ssh deploy@server 'secure-keystore import /app/production.skb production'

# 4. Verify with a real read. This is the step people skip.
ssh deploy@server 'secure-keystore get api_key "$USER_KEY" production'
```

The bundle is already encrypted, so interception alone exposes nothing. For
defence in depth you can encrypt it again for transit, but that is belt and
braces rather than the mechanism.

**Step 4 matters.** Import does not verify the user key — nothing does until
something decrypts. A store that copied cleanly but was written under a
different user key looks perfectly healthy until the application starts. Read a
key back as the last step of the deploy, and find out then.

Or copy the directory, which works just as well:

```bash
rsync -a .keystore/production/ deploy@server:/app/.keystore/production/
```

The bundle exists because one file is easier to hand to a CI system than a
directory, not because copying is unsafe.

---

## Phase 3 — Reading at run time

```javascript
// server.js
const { SecureKeystore } = require('@tech-style/secure-keystore');

const store = new SecureKeystore();
const userKey = process.env.USER_KEY;

// Decrypt what you need, when you need it
const jwtSecret = store.get('jwt_secret', userKey, 'production');
app.use(jwt({ secret: jwtSecret }));
```

Or everything at once, at boot:

```javascript
const secrets = store.getAll(userKey, 'production');
```

`getAll` costs **one** PBKDF2 derivation however many keys the store holds — the
user key is stretched once, and value keys come from HKDF. Format 2.0 stretched
the master key per value, which is why a twenty-key store used to take seconds.
Still do it once at start-up rather than per request.

Handle the failure that actually happens:

```javascript
const { ErrorCodes } = require('@tech-style/secure-keystore');

try {
  const apiKey = store.get('api_key', userKey, 'production');
} catch (error) {
  if (error.code === ErrorCodes.BAD_USER_KEY) {
    throw new Error('USER_KEY is wrong for this store — check the deploy');
  }
  if (error.code === ErrorCodes.STORE_NOT_FOUND) {
    throw new Error('The keystore has not been deployed to this machine');
  }
  throw error;
}
```

### Logging

The library prints nothing unless you ask it to. If you want its progress in
your own logs, hand it a function:

```javascript
const store = new SecureKeystore({ logger: message => logger.info({ msg: message }) });
```

---

## Common patterns

### One store per environment

```bash
secure-keystore secure dev-keys.env     "$DEV_KEY"     development
secure-keystore secure staging-keys.env "$STAGING_KEY" staging
secure-keystore secure prod-keys.env    "$PROD_KEY"    production
```

Different user keys per environment, so a leaked development key opens nothing
that matters.

### Rotating one secret

```bash
secure-keystore export production ./backups/prod-$(date +%Y%m%d).skb   # first
secure-keystore set api_key sk_live_new "$USER_KEY" production
```

The rewritten value gets a fresh salt and IV, so the new file gives nothing away
by comparison with the old one.

### Removing one

```bash
secure-keystore delete api_key production
```

No user key needed — deleting does not require reading.

### Auditing without a password

```bash
secure-keystore stores
secure-keystore list production
secure-keystore info production
```

Key names are stored in the clear, which is what makes this work. It also means
a key name must never itself be a secret.

### Bringing a store up to format 3.0

```bash
secure-keystore export production ./backups/prod-before-migrate.skb   # first
secure-keystore info production                                       # which format?
secure-keystore migrate production "$USER_KEY"
```

A store written by 1.x or 2.x keeps working untouched, and keeps taking 2.0
writes, so it is never half one format and half the other. `migrate` rewrites it
whole: 12-byte IVs, every value bound to its key name, and value keys derived
rather than stretched.

### A stronger store

```javascript
const store = new SecureKeystore({ iterations: 1000000 });
store.migrate('production', userKey);   // re-encrypts at the new count
```

The count is written into the store, so any reader follows it — including one on
the default settings, and including a future release with a different default.

### CI/CD

```yaml
# .github/workflows/deploy.yml
- name: Deploy secrets
  env:
    USER_KEY: ${{ secrets.KEYSTORE_USER_KEY }}
  run: |
    secure-keystore export production ./secrets.skb
    for server in ${{ env.SERVERS }}; do
      scp ./secrets.skb deploy@$server:/app/
      ssh deploy@$server "secure-keystore import /app/secrets.skb production"
      ssh deploy@$server "secure-keystore get api_key '$USER_KEY' production > /dev/null" \
        || { echo "::error::keystore unreadable on $server"; exit 1; }
    done
```

### Docker

```dockerfile
COPY .keystore /app/.keystore
# USER_KEY arrives at run time, never in a layer:
#   docker run -e USER_KEY="$USER_KEY" myapp
```

Never bake the user key into an image. The store may go in a layer; the key that
opens it may not.

---

## Encryption without a store

When the values live in a database rather than in a directory:

```javascript
const { encryptValue, decryptValue } = require('@tech-style/secure-keystore');

await db.insert({ name, token: encryptValue(apiToken, process.env.USER_KEY) });

const row = await db.findOne({ name });
const apiToken = decryptValue(row.token, process.env.USER_KEY);
```

`decryptValue` passes anything that is not a token straight through — and reads
both `skv2` and the older `skv1` — so a column part way through being encrypted
reads with one call:

```javascript
for (const row of await db.all('SELECT id, token FROM integrations')) {
  const plain = decryptValue(row.token, userKey);              // encrypted or not
  await db.run('UPDATE integrations SET token = ? WHERE id = ?',
    encryptValue(plain, userKey), row.id);
}
```

Run that twice and nothing breaks: the second pass decrypts what the first one
wrote.

**Choose the cost for bulk work.** A store pays one PBKDF2 stretch however many
keys it holds; a token pays one **per value**, so ten thousand rows at the
600,000 default is hours.

```javascript
encryptValue(plain, userKey, { iterations: 50000 });
```

The count is recorded in the token, so a column encrypted cheaply and a single
secret encrypted expensively both read back with the same call.

---

## Caveats worth knowing

- **`list`, `stores` and `info` need no user key.** Key names live in metadata in
  the clear. `get`, `all` and `set` decrypt, and do need one.
- **`get` without a store name searches every store**, and the first match wins.
  Name the store when more than one exists.
- **Importing does not verify the user key.** Reading a value does. End every
  deploy with a read.
- **Backups are `.skb` JSON bundles**, not tar archives — portable across
  operating systems and needing no external tool.
- **A store written by 1.x or 2.x keeps working**, and keeps taking 2.0 writes
  until you `migrate` it. `secure-keystore info` says which format it is on.
- **A decrypted value is plaintext in memory** for as long as your application
  holds it. This library encrypts values at rest, and cannot do anything about
  what happens after.
- **The user key is the whole root of trust.** Anyone who has it can read
  everything it opens. Treat it as a master password.

The full statement of what the format does and does not protect is
[SPEC.md §8](../SPEC.md#8-what-this-format-does-not-protect).
