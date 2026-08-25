import type { NextConfig } from "next";

const apiOrigin = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";

const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self' https://*.accounts.dev https://accounts.google.com",
  "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://*.clerk.accounts.dev",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https://img.clerk.com https://*.googleusercontent.com",
  "font-src 'self' data:",
  `connect-src 'self' ${apiOrigin} https://*.clerk.accounts.dev https://*.accounts.dev`,
  "frame-src https://*.accounts.dev https://*.clerk.accounts.dev https://accounts.google.com",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  "upgrade-insecure-requests",
].join("; ");

const nextConfig: NextConfig = {
  async headers() {
    return [{
      source: "/(.*)",
      headers: [
        { key: "Content-Security-Policy", value: contentSecurityPolicy },
        { key: "Referrer-Policy", value: "no-referrer" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "X-Frame-Options", value: "DENY" },
        { key: "Cross-Origin-Opener-Policy", value: "same-origin-allow-popups" },
        { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
      ],
    }];
  },
};

export default nextConfig;
