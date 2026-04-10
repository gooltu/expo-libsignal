import { NativeModule, requireNativeModule } from 'expo';

import { ExpoLibsignalModuleEvents } from './ExpoLibsignal.types';

declare class ExpoLibsignalModule extends NativeModule<ExpoLibsignalModuleEvents> {
  PI: number;
  hello(): string;
  setValueAsync(value: string): Promise<void>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ExpoLibsignalModule>('ExpoLibsignal');
