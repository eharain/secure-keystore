/**
 * Type definitions for @tech-style/secure-keystore.
 *
 * Hand-written rather than generated, because the shapes are small and the
 * comments are worth more than the generation would be.
 */

/** Options for a {@link SecureKeystore}. Every field has a default. */
export interface KeystoreOptions {
  /** Where stores live. Default `./.keystore` under the working directory. */
  keystoreDir?: string;
  /** PBKDF2 rounds the user key is stretched with, for new stores. Recorded in the store. Default 600000. */
  iterations?: number;
  /** Called with one line of progress. Default `null` - the library stays silent. */
  logger?: ((message: string) => void) | null;
  /** Create the keystore directory if it is absent. Default true. */
  createDir?: boolean;
}

/** What {@link SecureKeystore.secure} returns. */
export interface SecureResult {
  storeName: string;
  storeDir: string;
  totalKeys: number;
  keys: string[];
}

/** What {@link SecureKeystore.getStoreInfo} returns - no decryption involved. */
export interface StoreInfo {
  name: string;
  path: string;
  /** The store format version. `'3.0'` for anything written by this release. */
  version: string;
  /** False if the store is still in format 2.0 and would benefit from {@link SecureKeystore.migrate}. */
  current: boolean;
  created: string;
  updated: string;
  /** The PBKDF2 count this store's user key is stretched with. */
  iterations: number;
  totalKeys: number;
  keys: string[];
  sourceFile: string;
}

/** What {@link SecureKeystore.set} returns. */
export interface SetResult {
  key: string;
  storeName: string;
  /** True if the key was new, false if an existing value was replaced. */
  added: boolean;
  /** The format the record was written in - a 2.0 store keeps taking 2.0 writes. */
  format: string;
}

/** What {@link SecureKeystore.migrate} returns. */
export interface MigrateResult {
  storeName: string;
  /** The format the store was in before. */
  from: string;
  /** The format it is in now. */
  to: string;
  keys: string[];
  /** The PBKDF2 count it was rewritten with. */
  iterations: number;
}

/** Every code a {@link KeystoreError} can carry. */
export type ErrorCode =
  | 'INVALID_OPTIONS'
  | 'INVALID_ARGUMENT'
  | 'STORE_NOT_FOUND'
  | 'STORE_CORRUPT'
  | 'KEY_NOT_FOUND'
  | 'BAD_USER_KEY'
  | 'BAD_TOKEN'
  | 'BAD_INPUT'
  | 'BAD_BACKUP'
  | 'UNSUPPORTED_FORMAT';

/**
 * Thrown by every operation that can fail in a way a caller might handle rather
 * than merely report. The message may be reworded between releases; the code
 * will not be.
 */
export class KeystoreError extends Error {
  readonly name: 'KeystoreError';
  readonly code: ErrorCode;
  readonly cause?: Error;
  constructor(code: ErrorCode, message: string, options?: { cause?: Error });
}

export const ErrorCodes: { readonly [K in ErrorCode]: K };

/** The input formats an input file can be read as, chosen by extension. */
export const Formats: {
  readonly COLON: 'colon';
  readonly ENV: 'env';
  readonly JSON: 'json';
};

/** A secure key-value store backed by a directory. */
export class SecureKeystore {
  constructor(options?: KeystoreOptions);

  readonly options: Required<KeystoreOptions>;
  readonly keystoreDir: string;

  /** Encrypts a `.txt`, `.env` or `.json` key-value file into a store. */
  secure(inputFile: string, userKey: string, storeName?: string | null): SecureResult;

  /** Decrypts one value. With no store name, every store is searched. */
  get(key: string, userKey: string, storeName?: string | null): string;

  /** Decrypts every value in a store. */
  getAll(userKey: string, storeName: string): Record<string, string>;

  /** Adds a key or replaces an existing value. */
  set(key: string, value: string, userKey: string, storeName: string): SetResult;

  /**
   * Rewrites a whole store in the current format, under fresh salts and the
   * instance's iteration count. Use it to move a 2.0 store to 3.0, or to raise
   * the iteration count of a store already on 3.0.
   */
  migrate(storeName: string, userKey: string): MigrateResult;

  /** Removes one key and its encrypted file. */
  deleteKey(key: string, storeName: string): { key: string; storeName: string };

  /** The names of every store under this keystore directory. */
  listStores(): string[];

  /** The key names in a store. No user key needed - names are not encrypted. */
  listKeys(storeName: string): string[];

  /** Everything knowable about a store without decrypting anything. */
  getStoreInfo(storeName: string): StoreInfo;

  /** Writes a store to one portable `.skb` bundle. Returns the path. */
  exportStore(storeName: string, backupPath?: string | null): string;

  /** Restores a bundle. Returns the store name it was imported as. */
  importStore(backupPath: string, storeName?: string | null): string;

  /** Removes a store and its index entry. There is no undo. */
  deleteStore(storeName: string): { storeName: string };

  /** Instance sugar for the stateless {@link encryptValue}. */
  encryptValue(plaintext: string, userKey: string, options?: EncryptValueOptions): string;

  /** Instance sugar for the stateless {@link decryptValue}. */
  decryptValue(token: string, userKey: string): string;
}

/** Options for {@link encryptValue}. */
export interface EncryptValueOptions {
  /**
   * PBKDF2 rounds. Default 600000, and recorded in the token so decryption
   * follows whatever was chosen. Lower it when encrypting a whole column, where
   * the cost is paid per value rather than once per store.
   */
  iterations?: number;
}

/**
 * Encrypts one string under a user key, with nothing on disk. Returns an
 * `skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>` token. `null`,
 * `undefined` and `''` are returned unchanged.
 */
export function encryptValue(plaintext: string, userKey: string, options?: EncryptValueOptions): string;
export function encryptValue<T extends null | undefined | ''>(plaintext: T, userKey: string, options?: EncryptValueOptions): T;

/**
 * Reverses {@link encryptValue}, for `skv2` and the older `skv1`. Anything that
 * is not a token is returned unchanged; a token that is malformed, altered or
 * written under a different key throws.
 */
export function decryptValue(token: string, userKey: string): string;

/** True if the value is a token this library wrote, of either version. */
export function isEncryptedValue(value: unknown): value is string;

/** `'skv2'`, `'skv1'`, or null if the value is not a token. */
export function tokenVersion(value: unknown): 'skv1' | 'skv2' | null;

/** The options used when none are given. */
export function defaultOptions(): Required<KeystoreOptions>;

/** The version of this implementation. */
export const VERSION: string;

/** What this build actually does, for the compliance document. */
export const ALGORITHMS: {
  readonly cipher: 'aes-256-gcm';
  readonly ivBytes: 12;
  /** How the user key - a password - is stretched. Deliberately slow. */
  readonly passwordKdf: 'pbkdf2-hmac-sha256';
  readonly defaultIterations: number;
  /** How a value key comes from the master key. Fast, and correctly so. */
  readonly keyKdf: 'hkdf-sha256';
  readonly digest: 'sha256';
  readonly keyBits: 256;
  /** Whether a value is cryptographically bound to its key name. */
  readonly bindsKeyName: boolean;
};

/** The store format version this build writes. */
export const STORE_FORMAT_VERSION: string;
/** The older store format this build still reads and writes into. */
export const STORE_FORMAT_LEGACY: string;
/** The backup bundle version this build writes. */
export const BACKUP_VERSION: number;
/** The prefix every stateless value token carries. */
export const VALUE_TOKEN_PREFIX: string;

export default SecureKeystore;
