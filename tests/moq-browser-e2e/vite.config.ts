import path from "node:path";
import { defineConfig } from "vite";

const source = process.env.MOQ_DEV_SOURCE;
if (!source) throw new Error("MOQ_DEV_SOURCE must identify the exact moq-dev checkout");

export default defineConfig({
  resolve: {
    alias: {
      "@moq/net": path.join(source, "js/net/src/index.ts"),
      "@moq/signals": path.join(source, "js/signals/src/index.ts"),
      "@moq/qmux": path.join(process.cwd(), "node_modules/@moq/qmux/index.js"),
      "async-mutex": path.join(process.cwd(), "node_modules/async-mutex/index.mjs"),
      "zod/mini": path.join(process.cwd(), "node_modules/zod/mini/index.js")
    }
  },
  server: {
    fs: { allow: [source, process.cwd()] }
  }
});
