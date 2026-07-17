import * as Signal from '@signalapp/libsignal-client';

function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return window.btoa(binary);
}

function base64ToBuffer(base64: string): Uint8Array<ArrayBuffer> {
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
  return bytes as Uint8Array<ArrayBuffer>;
}

export class EncryptedSignalStore implements
  Signal.SessionStore,
  Signal.IdentityKeyStore,
  Signal.PreKeyStore,
  Signal.SignedPreKeyStore,
  Signal.KyberPreKeyStore
{
  private aesKey!: CryptoKey;

  public async initializeCrypto(storagePassword: string): Promise<void> {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw', enc.encode(storagePassword), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    this.aesKey = await window.crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: enc.encode('signal-secure-salt'), iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  private async saveEncrypted(key: string, data: Uint8Array<ArrayBuffer>): Promise<void> {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.aesKey, data);
    const payload = new Uint8Array(12 + ciphertext.byteLength);
    payload.set(iv, 0);
    payload.set(new Uint8Array(ciphertext), 12);
    localStorage.setItem(key, bufferToBase64(payload));
  }

  private async getEncrypted(key: string): Promise<Uint8Array<ArrayBuffer> | null> {
    const b64 = localStorage.getItem(key);
    if (!b64) return null;
    try {
      const payload = base64ToBuffer(b64);
      const iv = payload.slice(0, 12);
      const ciphertext = payload.slice(12);
      const plaintext = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.aesKey, ciphertext);
      return new Uint8Array(plaintext) as Uint8Array<ArrayBuffer>;
    } catch (e) {
      console.error(`Failed to decrypt storage key: ${key}`, e);
      return null;
    }
  }

  // ==========================================
  // IDENTITY KEY STORE
  // ==========================================

  async getIdentityKeyPair(): Promise<Signal.IdentityKeyPair> {
    const bytes = await this.getEncrypted('identityKeyPair');
    if (!bytes) throw new Error('Identity key pair not found');
    return Signal.IdentityKeyPair.deserialize(bytes);
  }

  // Required abstract method — delegates to getIdentityKeyPair().
  async getIdentityKey(): Promise<Signal.PrivateKey> {
    return (await this.getIdentityKeyPair()).privateKey;
  }

  async getLocalRegistrationId(): Promise<number> {
    const bytes = await this.getEncrypted('registrationId');
    if (!bytes) return 0;
    return new DataView(bytes.buffer).getUint32(0, true);
  }

  async saveIdentity(name: Signal.ProtocolAddress, key: Signal.PublicKey): Promise<Signal.IdentityChange> {
    const storageKey = `identity_${name.name()}_${name.deviceId()}`;
    const existingBytes = await this.getEncrypted(storageKey);
    const newBytes = key.serialize();
    await this.saveEncrypted(storageKey, newBytes);
    if (!existingBytes) return Signal.IdentityChange.NewOrUnchanged;
    const unchanged = existingBytes.length === newBytes.length && existingBytes.every((b, i) => b === newBytes[i]);
    return unchanged ? Signal.IdentityChange.NewOrUnchanged : Signal.IdentityChange.ReplacedExisting;
  }

  async getIdentity(name: Signal.ProtocolAddress): Promise<Signal.PublicKey | null> {
    const bytes = await this.getEncrypted(`identity_${name.name()}_${name.deviceId()}`);
    return bytes ? Signal.PublicKey.deserialize(bytes) : null;
  }

  async isTrustedIdentity(name: Signal.ProtocolAddress, key: Signal.PublicKey, _direction: Signal.Direction): Promise<boolean> {
    const trusted = await this.getIdentity(name);
    if (!trusted) return true; // Trust on First Use (TOFU)
    return trusted.equals(key);
  }

  // ==========================================
  // PRE KEY STORE
  // ==========================================

  async savePreKey(id: number, record: Signal.PreKeyRecord): Promise<void> {
    await this.saveEncrypted(`prekey_${id}`, record.serialize());
  }

  async getPreKey(id: number): Promise<Signal.PreKeyRecord> {
    const bytes = await this.getEncrypted(`prekey_${id}`);
    if (!bytes) throw new Error(`No PreKey with id ${id}`);
    return Signal.PreKeyRecord.deserialize(bytes);
  }

  async removePreKey(id: number): Promise<void> {
    localStorage.removeItem(`prekey_${id}`);
  }

  containsPreKey(id: number): boolean {
    return localStorage.getItem(`prekey_${id}`) !== null;
  }

  // ==========================================
  // SIGNED PRE KEY STORE
  // ==========================================

  async saveSignedPreKey(id: number, record: Signal.SignedPreKeyRecord): Promise<void> {
    await this.saveEncrypted(`signedprekey_${id}`, record.serialize());
  }

  async getSignedPreKey(id: number): Promise<Signal.SignedPreKeyRecord> {
    const bytes = await this.getEncrypted(`signedprekey_${id}`);
    if (!bytes) throw new Error(`No SignedPreKey with id ${id}`);
    return Signal.SignedPreKeyRecord.deserialize(bytes);
  }

  async removeSignedPreKey(id: number): Promise<void> {
    localStorage.removeItem(`signedprekey_${id}`);
  }

  containsSignedPreKey(id: number): boolean {
    return localStorage.getItem(`signedprekey_${id}`) !== null;
  }

  async loadSignedPreKeys(): Promise<Signal.SignedPreKeyRecord[]> {
    const records: Signal.SignedPreKeyRecord[] = [];
    for (const key of Object.keys(localStorage)) {
      if (!key.startsWith('signedprekey_')) continue;
      const bytes = await this.getEncrypted(key);
      if (bytes) records.push(Signal.SignedPreKeyRecord.deserialize(bytes));
    }
    return records;
  }

  // ==========================================
  // KYBER PRE KEY STORE
  // ==========================================

  async saveKyberPreKey(id: number, record: Signal.KyberPreKeyRecord): Promise<void> {
    await this.saveEncrypted(`kyberprekey_${id}`, record.serialize());
  }

  async getKyberPreKey(id: number): Promise<Signal.KyberPreKeyRecord> {
    const bytes = await this.getEncrypted(`kyberprekey_${id}`);
    if (!bytes) throw new Error(`No KyberPreKey with id ${id}`);
    return Signal.KyberPreKeyRecord.deserialize(bytes);
  }

  async markKyberPreKeyUsed(_id: number, _signedPreKeyId: number, _baseKey: Signal.PublicKey): Promise<void> {}

  containsKyberPreKey(id: number): boolean {
    return localStorage.getItem(`kyberprekey_${id}`) !== null;
  }

  async loadKyberPreKeys(): Promise<Signal.KyberPreKeyRecord[]> {
    const records: Signal.KyberPreKeyRecord[] = [];
    for (const key of Object.keys(localStorage)) {
      if (!key.startsWith('kyberprekey_')) continue;
      const bytes = await this.getEncrypted(key);
      if (bytes) records.push(Signal.KyberPreKeyRecord.deserialize(bytes));
    }
    return records;
  }

  // ==========================================
  // SESSION STORE
  // ==========================================

  async saveSession(name: Signal.ProtocolAddress, record: Signal.SessionRecord): Promise<void> {
    await this.saveEncrypted(`session_${name.name()}_${name.deviceId()}`, record.serialize());
  }

  async getSession(name: Signal.ProtocolAddress): Promise<Signal.SessionRecord | null> {
    const bytes = await this.getEncrypted(`session_${name.name()}_${name.deviceId()}`);
    return bytes ? Signal.SessionRecord.deserialize(bytes) : null;
  }

  async getExistingSessions(addresses: Signal.ProtocolAddress[]): Promise<Signal.SessionRecord[]> {
    const sessions: Signal.SessionRecord[] = [];
    for (const address of addresses) {
      const session = await this.getSession(address);
      if (session) sessions.push(session);
    }
    return sessions;
  }

  containsSession(address: Signal.ProtocolAddress): boolean {
    return localStorage.getItem(`session_${address.name()}_${address.deviceId()}`) !== null;
  }

  async deleteSession(address: Signal.ProtocolAddress): Promise<void> {
    localStorage.removeItem(`session_${address.name()}_${address.deviceId()}`);
  }

  async deleteAllSessions(name: string): Promise<void> {
    const prefix = `session_${name}_`;
    Object.keys(localStorage)
      .filter(k => k.startsWith(prefix))
      .forEach(k => localStorage.removeItem(k));
  }

  getSubDeviceSessions(name: string): number[] {
    const prefix = `session_${name}_`;
    return Object.keys(localStorage)
      .filter(k => k.startsWith(prefix))
      .map(k => parseInt(k.slice(prefix.length), 10))
      .filter(id => !isNaN(id));
  }

  // ==========================================
  // MODULE DIRECT SAVERS
  // ==========================================

  public async storeIdentityKeyPair(kp: Signal.IdentityKeyPair): Promise<void> {
    await this.saveEncrypted('identityKeyPair', kp.serialize() as Uint8Array<ArrayBuffer>);
  }

  public async storeLocalRegistrationId(id: number): Promise<void> {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(0, id, true);
    await this.saveEncrypted('registrationId', new Uint8Array(buf) as Uint8Array<ArrayBuffer>);
  }
}
