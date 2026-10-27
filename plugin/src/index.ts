import { ConfigPlugin, withProjectBuildGradle, withAppBuildGradle } from '@expo/config-plugins';

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

const withExpoLibsignal: ConfigPlugin = (config) => {
  config = withSignalMavenRepo(config);
  config = withSignalCoreLibraryDesugaring(config);
  return config;
};

export default withExpoLibsignal;