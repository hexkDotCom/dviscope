import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The production build has no inline scripts or styles (CSP: script-src 'self').
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false, assetsInlineLimit: 0 },
  test: { environment: "jsdom", globals: true },
});
