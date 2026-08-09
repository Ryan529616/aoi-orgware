import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/company-os/",
  plugins: [react()],
  build: {
    target: "es2022",
    sourcemap: false,
    assetsInlineLimit: 0,
    emptyOutDir: true,
    outDir: "../../src/aoi_orgware/resources/dashboard_company_os"
  },
  server: {
    strictPort: true
  },
  test: {
    environment: "jsdom"
  }
});
