import { ConfigPlugin, withProjectBuildGradle } from '@expo/config-plugins';

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

export default withSignalMavenRepo;