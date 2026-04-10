import { registerWebModule, NativeModule } from 'expo';

import { ExpoLibsignalModuleEvents } from './ExpoLibsignal.types';

class ExpoLibsignalModule extends NativeModule<ExpoLibsignalModuleEvents> {
  PI = Math.PI;
  async setValueAsync(value: string): Promise<void> {
    this.emit('onChange', { value });
  }
  hello() {
    return 'Hello world! 👋';
  }
}

export default registerWebModule(ExpoLibsignalModule, 'ExpoLibsignalModule');
