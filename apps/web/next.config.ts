import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Keep production builds from overwriting a running development server's chunks.
  distDir: process.env.NODE_ENV === 'development' ? '.next-dev' : '.next',
  reactStrictMode: false, // Prevents duplicate SSE connections in development mode
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://127.0.0.1:4000/api/:path*",
      },
    ];
  },
};

export default nextConfig;
