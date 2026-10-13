import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// shortcut: stock vite react plugin added here for JSX. It is the standard
// pairing and cheaper than hand-rolled transforms.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { port: 5173 }
});
