import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://udid-tools.github.io",
  base: "/core/",
  integrations: [
    starlight({
      title: "UDID Tools Core",
      description:
        "TypeScript SDK for Apple Profile Service profiles, CMS signing, verification, and response parsing.",
      logo: {
        src: "./src/assets/logo-header.svg",
        alt: "UDID Tools",
      },
      customCss: ["./src/styles/custom.css"],
      editLink: {
        baseUrl: "https://github.com/udid-tools/core/edit/main/docs/",
      },
      head: [
        {
          tag: "meta",
          attrs: {
            property: "og:image",
            content: "https://udid-tools.github.io/core/og.png",
          },
        },
        {
          tag: "meta",
          attrs: {
            property: "og:image:alt",
            content: "UDID Tools Core — Apple Profile Service toolkit for TypeScript",
          },
        },
        {
          tag: "meta",
          attrs: { property: "og:image:width", content: "1729" },
        },
        {
          tag: "meta",
          attrs: { property: "og:image:height", content: "910" },
        },
        {
          tag: "meta",
          attrs: {
            name: "twitter:card",
            content: "summary_large_image",
          },
        },
        {
          tag: "meta",
          attrs: {
            name: "twitter:image",
            content: "https://udid-tools.github.io/core/og.png",
          },
        },
        {
          tag: "meta",
          attrs: {
            name: "twitter:image:alt",
            content: "UDID Tools Core — Apple Profile Service toolkit for TypeScript",
          },
        },
      ],
      lastUpdated: true,
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/udid-tools/core",
        },
      ],
      sidebar: [
        {
          label: "Start here",
          items: [
            { label: "Overview", slug: "index" },
            { label: "Installation", slug: "getting-started/installation" },
            { label: "Quick start", slug: "getting-started/quick-start" },
          ],
        },
        {
          label: "Guides",
          items: [{ autogenerate: { directory: "guides" } }],
        },
        {
          label: "Concepts",
          items: [{ autogenerate: { directory: "concepts" } }],
        },
        {
          label: "Reference",
          items: [{ autogenerate: { directory: "reference" } }],
        },
        {
          label: "Project",
          items: [{ autogenerate: { directory: "project" } }],
        },
      ],
    }),
  ],
});
