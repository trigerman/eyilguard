import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, the UI runs on Vite's server and proxies API + WebSocket calls to the
// engine. In the packaged product the engine serves the built UI itself, so the
// frontend talks to its own origin and no proxy is involved.
const ENGINE = "http://127.0.0.1:8787";

export default defineConfig({
  root: __dirname,
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/objects": ENGINE,
      "/health": ENGINE,
      "/scan": ENGINE,
      "/events": ENGINE,
      "/stream": { target: ENGINE, ws: true },
    },
  },
});
