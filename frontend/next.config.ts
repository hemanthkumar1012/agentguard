import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Vercel manages the Next.js runtime/output itself. Keep standalone only
  // for non-Vercel container deployments such as the frontend Docker image.
  ...(process.env.VERCEL ? {} : { output: "standalone" }),
  poweredByHeader: false,

  // Vercel's file tracer can miss the ESM branches of @swc/helpers
  // when collecting Next.js serverless function files. Explicitly include
  // the helper package so the deployment contains both CJS and ESM helpers.
  outputFileTracingIncludes: {
    "*": ["./node_modules/@swc/helpers/**"],
  },
};

export default nextConfig;
