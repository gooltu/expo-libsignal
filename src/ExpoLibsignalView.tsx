import { requireNativeView } from 'expo';
import * as React from 'react';

import { ExpoLibsignalViewProps } from './ExpoLibsignal.types';

const NativeView: React.ComponentType<ExpoLibsignalViewProps> =
  requireNativeView('ExpoLibsignal');

export default function ExpoLibsignalView(props: ExpoLibsignalViewProps) {
  return <NativeView {...props} />;
}
