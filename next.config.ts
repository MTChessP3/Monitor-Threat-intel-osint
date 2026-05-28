import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: false,
  output: "standalone",
  allowedDevOrigins: [
    "preview-chat-ea108c17-27a0-44c2-8b22-7d10d131da48.space-z.ai",
    ".space.chatglm.site",
    ".space-z.ai",
  ],
};

export default nextConfig;
