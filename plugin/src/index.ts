import {
  ConfigPlugin,
  withProjectBuildGradle,
  withAppBuildGradle,
  withPodfile,
  withPodfileProperties,
} from '@expo/config-plugins';

const withSignalMavenRepo: ConfigPlugin = (config) => {
  return withProjectBuildGradle(config, async (config) => {
    const buildGradle = config.modResults.contents;
    const signalRepo = "maven { url 'https://build-artifacts.signal.org/libraries/maven/' }";

    // Check if it's already added to prevent duplicates
    if (!buildGradle.includes('build-artifacts.signal.org')) {
      // Inject the maven repo into the root allprojects > repositories block
      config.modResults.contents = buildGradle.replace(
        /allprojects\s*{\s*repositories\s*{/,
        `allprojects {\n    repositories {\n        ${signalRepo}`
      );
    }

    return config;
  });
};

// org.signal:libsignal-android ships Java 8+ APIs (java.time, streams, etc.)
// via desugaring in its own AAR, and requires the *consuming* app module to
// enable core library desugaring too — otherwise the build fails with
// "Dependency 'org.signal:libsignal-android:...' requires core library
// desugaring to be enabled for :app". See
// https://developer.android.com/studio/write/java8-support.html
const withSignalCoreLibraryDesugaring: ConfigPlugin = (config) => {
  return withAppBuildGradle(config, (config) => {
    let buildGradle = config.modResults.contents;

    if (!buildGradle.includes('coreLibraryDesugaringEnabled')) {
      buildGradle = buildGradle.replace(
        /android\s*{/,
        `android {\n    compileOptions {\n        coreLibraryDesugaringEnabled true\n        sourceCompatibility JavaVersion.VERSION_1_8\n        targetCompatibility JavaVersion.VERSION_1_8\n    }\n`
      );
    }

    if (!buildGradle.includes('coreLibraryDesugaring ')) {
      buildGradle = buildGradle.replace(
        /dependencies\s*{/,
        `dependencies {\n    coreLibraryDesugaring 'com.android.tools:desugar_jdk_libs:2.1.4'\n`
      );
    }

    config.modResults.contents = buildGradle;
    return config;
  });
};

// LibSignalClient (the iOS/Swift pod) is not published to the CocoaPods trunk
// spec repo, so a plain `s.dependency 'LibSignalClient'` in
// ios/ExpoLibsignal.podspec can never resolve on its own — CocoaPods needs an
// explicit git-based source, plus the matching prebuilt-binary checksum,
// declared directly in the consuming app's Podfile. Version/checksum pinned
// to the same 0.86.5 release used by Android's org.signal:libsignal-android.
// See https://github.com/signalapp/libsignal/blob/main/swift/README.md and
// https://github.com/signalapp/libsignal/releases/tag/v0.86.5.
const LIBSIGNAL_IOS_VERSION = '0.86.5';
const LIBSIGNAL_IOS_CHECKSUM =
  'a3df979aa39b307ac4ef0f3fd59536daab5d6b3f8257c7aefe5f0470625f2582';

const withSignalPod: ConfigPlugin = (config) => {
  // LibSignalClient is a Swift pod and, per its own README, "cannot be
  // compiled as a plain library" — the consuming app's Podfile must use
  // use_frameworks!. This must be DYNAMIC linkage specifically: the pod's own
  // libsignal_ffi.a (the prebuilt Rust FFI static lib fetched by its script
  // phases) only gets linked in via its `OTHER_LDFLAGS` pod_target_xcconfig
  // entry, which is honored by the real `clang -dynamiclib` link step a
  // dynamic framework gets — a static framework instead builds via
  // `libtool -static`, which ignores OTHER_LDFLAGS entirely and silently
  // produces a LibSignalClient.framework missing all of libsignal_ffi's
  // symbols (undefined symbols at the final app link instead).
  config = withPodfileProperties(config, (config) => {
    if (!config.modResults['ios.useFrameworks']) {
      config.modResults['ios.useFrameworks'] = 'dynamic';
    }
    return config;
  });

  return withPodfile(config, (config) => {
    let podfile = config.modResults.contents;

    if (!podfile.includes('LibSignalClient')) {
      podfile = podfile.replace(
        /use_expo_modules!/,
        `use_expo_modules!\n\n  pod 'LibSignalClient', git: 'https://github.com/signalapp/libsignal.git', tag: 'v${LIBSIGNAL_IOS_VERSION}'\n  ENV['LIBSIGNAL_FFI_PREBUILD_CHECKSUM'] = '${LIBSIGNAL_IOS_CHECKSUM}'`
      );
      config.modResults.contents = podfile;
    }

    return config;
  });
};

const withExpoLibsignal: ConfigPlugin = (config) => {
  config = withSignalMavenRepo(config);
  config = withSignalCoreLibraryDesugaring(config);
  config = withSignalPod(config);
  return config;
};

export default withExpoLibsignal;