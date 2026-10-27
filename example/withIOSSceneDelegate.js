const { withDangerousMod, withXcodeProject } = require('@expo/config-plugins');
const fs = require('fs');
const path = require('path');

// This Xcode/iOS SDK (as of this writing, a pre-release version ahead of
// Expo SDK 54 / React Native 0.81) hard-requires a real UIScene lifecycle to
// launch at all -- a bare UIApplicationSceneManifest in Info.plist is not
// enough. React Native 0.81's RCTAppDelegate/RCTReactNativeFactory have no
// built-in scene support (confirmed against RN up to the current latest,
// 0.88 -- its own header says UIScene apps must "implement your own
// SceneDelegate with RCTReactNativeFactory"), so this adds the minimal one
// by hand: AppDelegate keeps creating the RCTReactNativeFactory/delegate
// (unchanged), but window creation + factory.startReactNative(...) move
// from AppDelegate.application(_:didFinishLaunchingWithOptions:) into
// SceneDelegate.scene(_:willConnectTo:options:), which is the standard,
// minimal-change way to bridge a classic window-based RN app onto UIScene.
// See app.json's ios.infoPlist UIApplicationSceneManifest for the
// Info.plist half of this (UISceneDelegateClassName: "SceneDelegate").

const SCENE_DELEGATE_CONTENT = `import UIKit
import Expo
import React

@objc(SceneDelegate)
class SceneDelegate: UIResponder, UIWindowSceneDelegate {
  var window: UIWindow?

  func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
    guard let windowScene = scene as? UIWindowScene,
          let appDelegate = UIApplication.shared.delegate as? AppDelegate,
          let factory = appDelegate.reactNativeFactory else {
      return
    }

    let window = UIWindow(windowScene: windowScene)
    self.window = window
    appDelegate.window = window

    factory.startReactNative(
      withModuleName: "main",
      in: window,
      launchOptions: nil)
  }
}
`;

const OLD_WINDOW_BLOCK = `#if os(iOS) || os(tvOS)
    window = UIWindow(frame: UIScreen.main.bounds)
    factory.startReactNative(
      withModuleName: "main",
      in: window,
      launchOptions: launchOptions)
#endif

`;

function withSceneDelegateFile(config) {
  return withDangerousMod(config, [
    'ios',
    (config) => {
      const iosRoot = config.modRequest.platformProjectRoot;
      const targetName = config.modRequest.projectName;

      const sceneDelegatePath = path.join(iosRoot, targetName, 'SceneDelegate.swift');
      fs.writeFileSync(sceneDelegatePath, SCENE_DELEGATE_CONTENT);

      const appDelegatePath = path.join(iosRoot, targetName, 'AppDelegate.swift');
      const appDelegateContents = fs.readFileSync(appDelegatePath, 'utf-8');
      if (appDelegateContents.includes(OLD_WINDOW_BLOCK)) {
        fs.writeFileSync(appDelegatePath, appDelegateContents.replace(OLD_WINDOW_BLOCK, ''));
      }

      return config;
    },
  ]);
}

function withSceneDelegateXcodeTarget(config) {
  return withXcodeProject(config, (config) => {
    const project = config.modResults;
    const targetName = config.modRequest.projectName;
    const filePath = `${targetName}/SceneDelegate.swift`;

    const alreadyAdded = Object.values(project.hash.project.objects['PBXFileReference'] || {}).some(
      (f) => typeof f === 'object' && f.path === '"SceneDelegate.swift"'
    );

    if (!alreadyAdded) {
      const groupKey = project.findPBXGroupKey({ name: targetName });
      project.addSourceFile(filePath, {}, groupKey);
    }

    return config;
  });
}

module.exports = (config) => {
  config = withSceneDelegateFile(config);
  config = withSceneDelegateXcodeTarget(config);
  return config;
};
