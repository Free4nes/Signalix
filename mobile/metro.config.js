const { getDefaultConfig } = require("expo/metro-config");
const path = require("path");

const projectRoot = __dirname;

const config = getDefaultConfig(projectRoot);

// Restrict module resolution to this project's own node_modules only.
// This prevents Metro from walking up to the repo root and picking up
// packages from web/ or other workspaces (which caused "Unable to resolve react").
config.resolver.nodeModulesPaths = [path.resolve(projectRoot, "node_modules")];

// Only watch the mobile/ folder — not the entire monorepo.
config.watchFolders = [projectRoot];

module.exports = config;
