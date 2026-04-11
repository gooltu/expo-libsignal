import { registerWebModule, NativeModule } from 'expo';

import { IdentityKeyPair, PreKeyRecord, SignedPreKeyRecord} from './ExpoLibsignal.types';

class ExpoLibsignalModule extends NativeModule {
  // PI = Math.PI;
  // async setValueAsync(value: string): Promise<void> {
  //   this.emit('onChange', { value });
  // }
  // hello() {
  //   return 'Hello world! 👋';
  // }

  async generateIdentityKeyPair(): Promise<IdentityKeyPair> {  
    
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        const success = true;
        if (success) {
          resolve({
            publicKey: 'ikp.publicKeyweb',
            privateKey: 'ikp.privateKeyweb'
          }); // Resolve with a string value
        } else {
          reject('Failed to generate identity key pair'); // Reject with an error or reason
        }
      }, 1000);
    });

  }

  async generateRegistrationId(): Promise<number>{

    return new Promise((resolve, reject) => {
      setTimeout(() => {
        const success = true;
        if (success) {
          resolve(1234567890); // Resolve with a string value
        } else {
          reject('Failed to generate registration id'); // Reject with an error or reason
        }
      }, 1000);
    });
  }

  async generatePreKeys(startId: number, count: number): Promise<PreKeyRecord[]> {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        const success = true;
        if (success) {
          resolve([{
            id: 1,
            publicKey: 'web.publicKey',   
            privateKey: 'web.privateKey'           
          }]); 
        } else {
          reject('Failed to generate PreKeys'); // Reject with an error or reason
        }
      }, 1000);
    });
  }

  async generateSignedPreKey(identityKeyPair: IdentityKeyPair, signedPreKeyId: number): Promise<SignedPreKeyRecord> {
  
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        const success = true;
        if (success) {
          resolve({
            id: 1,
            publicKey: 'web.publicKey',   
            privateKey: 'web.privateKey',
            signature: 'web.signature',
            timestamp: 0           
          }); 
        } else {
          reject('Failed to generate Signed PreKey Record'); // Reject with an error or reason
        }
      }, 1000);
    });  
    
  }


}

export default registerWebModule(ExpoLibsignalModule, 'ExpoLibsignalModule');
