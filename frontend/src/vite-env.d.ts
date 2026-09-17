/// <reference types="vite/client" />

/**
 * Injected at build time by vite.config.ts from package.json's `version`.
 * Keep it that way: the login footer used to hardcode the string, which is how
 * the UI sat on v0.3.0 while the repo had moved on to 0.6.1.
 */
declare const __APP_VERSION__: string;
