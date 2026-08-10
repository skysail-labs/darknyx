// Some circomlibjs transitive dependencies still reference Node globals.
// esbuild injects these bindings only into modules that use them, keeping the
// application source browser-native without relying on mutable globals.
export { Buffer } from "buffer";
export { default as process } from "process";
