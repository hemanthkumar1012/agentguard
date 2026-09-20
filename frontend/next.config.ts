import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Vercel manages the Next.js runtime/output itself. Keep standalone only
  // for non-Vercel container deployments such as the frontend Docker image.
  ...(process.env.VERCEL ? {} : { output: "standalone" }),
  poweredByHeader: false,
};

export default nextConfig;
