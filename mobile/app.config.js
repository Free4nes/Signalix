// Single source of truth for Expo app configuration.
// All build-time identity values live here; eas.json references them via
// cli.appVersionSource="local" so EAS never auto-increments versionCode.
//
// Single source of truth for package identifiers. Display name: "Signalix".

/** @type {import('expo/config').ExpoConfig} */
const config = {
  name: "Signalix",
  slug: "signalix",
  version: "1.0.0",
  orientation: "portrait",
  icon: "./assets/icon.png",
  userInterfaceStyle: "light",
  newArchEnabled: true,
  splash: {
    image: "./assets/signalix-splash.png",
    resizeMode: "contain",
    backgroundColor: "#ffffff",
  },
  ios: {
    bundleIdentifier: "com.signalix",
    buildNumber: "17",
    supportsTablet: true,
  },
  android: {
    package: "com.signalix",
    versionCode: 17,
    permissions: ["POST_NOTIFICATIONS"],
    googleServicesFile: process.env.GOOGLE_SERVICES_JSON ?? "./google-services.json",
    adaptiveIcon: {
      foregroundImage: "./assets/adaptive-icon.png",
      backgroundColor: "#5aa6d6",
    },
    targetSdkVersion: 35,
    usesCleartextTraffic: true,
    networkSecurityConfig: "./network_security_config.xml",
  },
  web: {
    bundler: "metro",
    output: "static",
    favicon: "./assets/favicon.png",
  },
  plugins: [
    "expo-router",
    "expo-dev-client",
    [
      "expo-notifications",
      {
        icon: "./assets/icon.png",
        color: "#ffffff",
        defaultChannel: "default",
      },
    ],
  ],
  experiments: {
    typedRoutes: true,
  },
  scheme: "signalix",
  extra: {
    eas: {
      projectId: "a1be1ac3-1e39-4d5f-abf8-4820c4943dad",
    },
    apiBaseUrl: process.env.EXPO_PUBLIC_API_HOST,
  },
};

module.exports = config;
