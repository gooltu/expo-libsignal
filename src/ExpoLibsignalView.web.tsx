import * as React from 'react';

import { ExpoLibsignalViewProps } from './ExpoLibsignal.types';

export default function ExpoLibsignalView(props: ExpoLibsignalViewProps) {
  return (
    <div>
      <iframe
        style={{ flex: 1 }}
        src={props.url}
        onLoad={() => props.onLoad({ nativeEvent: { url: props.url } })}
      />
    </div>
  );
}
