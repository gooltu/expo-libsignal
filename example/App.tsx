import Libsignal from 'expo-libsignal';
import { useState, useEffect } from 'react';
import {
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import type { ProtocolAddress } from 'expo-libsignal';

export default function App() {
  const [localName, setLocalName] = useState('');
  const [initialized, setInitialized] = useState(false);
  const [initError, setInitError] = useState('');

  const [generatedBundle, setGeneratedBundle] = useState('');
  const [bundleError, setBundleError] = useState('');

  const [recipientBundleText, setRecipientBundleText] = useState('');
  const [sessionStatus, setSessionStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [sessionError, setSessionError] = useState('');
  const [recipientAddress, setRecipientAddress] = useState<ProtocolAddress | null>(null);

  const [messageToEncrypt, setMessageToEncrypt] = useState('');
  const [encryptedMessage, setEncryptedMessage] = useState('');
  const [encryptError, setEncryptError] = useState('');

  const [messageToDecrypt, setMessageToDecrypt] = useState('');
  const [decryptedMessage, setDecryptedMessage] = useState('');
  const [decryptError, setDecryptError] = useState('');

  useEffect(() => {
    const init = async () => {
      try {
        const name = crypto.randomUUID();
        await Libsignal.initialize('demo-password-fixed', name, 1);
        setLocalName(name);
        setInitialized(true);
      } catch (e: any) {
        setInitError(e?.message ?? String(e));
      }
    };
    init();
  }, []);

  const handleGenerateBundle = async () => {
    setBundleError('');
    setGeneratedBundle('');
    try {
      const identityKeyPair = await Libsignal.generateIdentityKeyPair();
      const registrationId = await Libsignal.generateRegistrationId();
      const preKeys = await Libsignal.generatePreKeys(1, 1);
      const signedPreKey = await Libsignal.generateSignedPreKey(identityKeyPair, 1);

      const bundle = {
        name: localName,
        deviceId: 1,
        registrationId,
        identityKey: identityKeyPair.publicKey,
        preKeyId: preKeys[0].id,
        preKeyPublic: preKeys[0].publicKey,
        signedPreKeyId: signedPreKey.id,
        signedPreKeyPublic: signedPreKey.publicKey,
        signedPreKeySignature: signedPreKey.signature,
      };
      setGeneratedBundle(JSON.stringify(bundle, null, 2));
    } catch (e: any) {
      setBundleError(e?.message ?? String(e));
    }
  };

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Silently ignore — clipboard is non-critical
    }
  };

  const handleBuildSession = async () => {
    setSessionStatus('idle');
    setSessionError('');
    setRecipientAddress(null);
    try {
      const bundle = JSON.parse(recipientBundleText);
      if (!bundle.name || !bundle.deviceId) {
        throw new Error('Bundle must include "name" and "deviceId" fields.');
      }
      const address: ProtocolAddress = { name: bundle.name, deviceId: bundle.deviceId };
      await Libsignal.processPreKeyBundle(address, bundle);
      setRecipientAddress(address);
      setSessionStatus('success');
    } catch (e: any) {
      setSessionStatus('error');
      setSessionError(e?.message ?? String(e));
    }
  };

  const handleEncrypt = async () => {
    setEncryptError('');
    setEncryptedMessage('');
    if (!recipientAddress) {
      setEncryptError('Build a session first.');
      return;
    }
    try {
      const result = await Libsignal.encryptMessage(recipientAddress, messageToEncrypt);
      setEncryptedMessage(JSON.stringify(result));
    } catch (e: any) {
      setEncryptError(e?.message ?? String(e));
    }
  };

  const handleDecrypt = async () => {
    setDecryptError('');
    setDecryptedMessage('');
    if (!recipientAddress) {
      setDecryptError('Build a session first.');
      return;
    }
    try {
      const ciphertext = JSON.parse(messageToDecrypt);
      const result = await Libsignal.decryptMessage(recipientAddress, ciphertext);
      setDecryptedMessage(
        typeof result === 'string' ? result : new TextDecoder().decode(result as Uint8Array),
      );
    } catch (e: any) {
      setDecryptError(e?.message ?? String(e));
    }
  };

  const handleErase = async () => {
    try {
      await Libsignal.eraseSession();
      const newName = crypto.randomUUID();
      await Libsignal.initialize('demo-password-fixed', newName, 1);
      setLocalName(newName);
      setGeneratedBundle('');
      setBundleError('');
      setRecipientBundleText('');
      setSessionStatus('idle');
      setSessionError('');
      setRecipientAddress(null);
      setMessageToEncrypt('');
      setEncryptedMessage('');
      setEncryptError('');
      setMessageToDecrypt('');
      setDecryptedMessage('');
      setDecryptError('');
    } catch (e: any) {
      setBundleError('Erase failed: ' + (e?.message ?? String(e)));
    }
  };

  return (
    <SafeAreaView style={styles.safeArea}>
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        {!initialized && !initError && (
          <Text style={styles.statusText}>Initializing…</Text>
        )}
        {!!initError && (
          <Text style={styles.errorText}>Init error: {initError}</Text>
        )}

        {/* Section 1: Generate Bundle */}
        <TouchableOpacity
          style={[styles.blackButton, !initialized && styles.disabledButton]}
          onPress={handleGenerateBundle}
          disabled={!initialized}
        >
          <Text style={styles.blackButtonText}>Generate bundle</Text>
        </TouchableOpacity>

        <TextInput
          style={styles.textarea}
          multiline
          editable={false}
          value={generatedBundle}
          placeholder="textarea1"
          placeholderTextColor="#aaa"
        />

        <View style={styles.row}>
          <View style={{ flex: 1 }} />
          <TouchableOpacity onPress={() => handleCopy(generatedBundle)} disabled={!generatedBundle}>
            <Text style={[styles.copyLink, !generatedBundle && styles.disabledText]}>
              Copy bundle
            </Text>
          </TouchableOpacity>
        </View>

        {!!bundleError && <Text style={styles.errorText}>{bundleError}</Text>}

        {/* Section 2: Build Session */}
        <Text style={styles.sectionLabel}>Paste recipient bundle</Text>
        <TextInput
          style={styles.textarea}
          multiline
          placeholder="textarea2"
          placeholderTextColor="#aaa"
          value={recipientBundleText}
          onChangeText={setRecipientBundleText}
        />

        <TouchableOpacity
          style={[styles.blackButton, (!initialized || !recipientBundleText.trim()) && styles.disabledButton]}
          onPress={handleBuildSession}
          disabled={!initialized || !recipientBundleText.trim()}
        >
          <Text style={styles.blackButtonText}>Build session</Text>
        </TouchableOpacity>

        {sessionStatus === 'success' && (
          <Text style={styles.successText}>Session successfully created</Text>
        )}
        {sessionStatus === 'error' && (
          <Text style={styles.errorText}>{sessionError}</Text>
        )}

        <View style={styles.divider} />

        {/* Section 3: Encrypt */}
        <Text style={styles.sectionLabel}>Message to encrypt</Text>
        <TextInput
          style={styles.textbox}
          placeholder="textbox3"
          placeholderTextColor="#aaa"
          value={messageToEncrypt}
          onChangeText={setMessageToEncrypt}
        />

        <TouchableOpacity
          style={[styles.blackButton, (!recipientAddress || !messageToEncrypt.trim()) && styles.disabledButton]}
          onPress={handleEncrypt}
          disabled={!recipientAddress || !messageToEncrypt.trim()}
        >
          <Text style={styles.blackButtonText}>Encrypt message</Text>
        </TouchableOpacity>

        {!!encryptError && <Text style={styles.errorText}>{encryptError}</Text>}

        <Text style={styles.sectionLabel}>Encrypted message</Text>
        <TextInput
          style={styles.textbox}
          editable={false}
          value={encryptedMessage}
          placeholder='textbox4'
          placeholderTextColor="#aaa"
        />

        <View style={styles.divider} />

        {/* Section 4: Decrypt */}
        <Text style={styles.sectionLabel}>Message to decrypt</Text>
        <TextInput
          style={styles.textbox}
          placeholder='textbox5'
          placeholderTextColor="#aaa"
          value={messageToDecrypt}
          onChangeText={setMessageToDecrypt}
        />

        <TouchableOpacity
          style={[styles.blackButton, (!recipientAddress || !messageToDecrypt.trim()) && styles.disabledButton]}
          onPress={handleDecrypt}
          disabled={!recipientAddress || !messageToDecrypt.trim()}
        >
          <Text style={styles.blackButtonText}>Decrypt message</Text>
        </TouchableOpacity>

        {!!decryptError && <Text style={styles.errorText}>{decryptError}</Text>}

        <Text style={styles.sectionLabel}>Decrypted message</Text>
        <TextInput
          style={styles.textbox}
          editable={false}
          value={decryptedMessage}
          placeholder="textbox6"
          placeholderTextColor="#aaa"
        />

        <View style={styles.divider} />

        {/* Section 5: Erase */}
        <TouchableOpacity
          style={[styles.blackButton, styles.eraseButton, !initialized && styles.disabledButton]}
          onPress={handleErase}
          disabled={!initialized}
        >
          <Text style={styles.blackButtonText}>Erase Session</Text>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: '#fff',
  },
  container: {
    flex: 1,
  },
  content: {
    padding: 16,
  },
  blackButton: {
    backgroundColor: '#000',
    borderRadius: 6,
    paddingVertical: 14,
    alignItems: 'center',
    marginBottom: 8,
  },
  disabledButton: {
    backgroundColor: '#555',
  },
  blackButtonText: {
    color: '#fff',
    fontWeight: '600',
    fontSize: 16,
  },
  textarea: {
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 6,
    padding: 10,
    minHeight: 120,
    textAlignVertical: 'top',
    fontFamily: 'monospace',
    fontSize: 12,
    marginBottom: 8,
    color: '#000',
  },
  textbox: {
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 6,
    padding: 10,
    fontSize: 14,
    marginBottom: 8,
    color: '#000',
  },
  sectionLabel: {
    fontWeight: '700',
    fontSize: 15,
    marginBottom: 6,
    marginTop: 4,
  },
  copyLink: {
    color: '#0066cc',
    fontWeight: '600',
    fontSize: 14,
    marginBottom: 8,
  },
  disabledText: {
    color: '#aaa',
  },
  successText: {
    color: '#16a34a',
    fontWeight: '600',
    fontSize: 14,
    marginBottom: 8,
    textAlign: 'center',
  },
  errorText: {
    color: '#dc2626',
    fontSize: 13,
    marginBottom: 8,
  },
  statusText: {
    color: '#666',
    fontSize: 13,
    marginBottom: 8,
  },
  divider: {
    height: 1,
    backgroundColor: '#e5e7eb',
    marginVertical: 12,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  eraseButton: {
    marginBottom: 40,
  },
});
