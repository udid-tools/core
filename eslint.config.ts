import eslint from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
  {
    ignores: [
      "coverage/**",
      "dist/**",
      "docs/.astro/**",
      "docs/dist/**",
      "docs/docs/**",
      "docs/node_modules/**",
      "node_modules/**",
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/consistent-type-exports": "error",
      "@typescript-eslint/consistent-type-imports": ["error", { fixStyle: "inline-type-imports" }],
      "@typescript-eslint/explicit-function-return-type": [
        "error",
        { allowExpressions: true, allowTypedFunctionExpressions: true },
      ],
      "@typescript-eslint/no-confusing-void-expression": "off",
      "@typescript-eslint/no-unsafe-assignment": "error",
      "@typescript-eslint/no-unsafe-argument": "error",
      "@typescript-eslint/no-unsafe-member-access": "error",
      "@typescript-eslint/only-throw-error": "error",
    },
  },
  {
    files: ["src/profile-service/**/*.ts", "src/validation/**/*.ts"],
    rules: {
      // These files are runtime trust boundaries. The public TypeScript types do
      // not remove the need to reject malformed JavaScript input defensively.
      "@typescript-eslint/no-unnecessary-condition": "off",
    },
  },
  {
    files: ["src/profile-service/generate.ts"],
    rules: {
      // Keep the public API asynchronous so future signing providers can be
      // added without a breaking return-type change.
      "@typescript-eslint/require-await": "off",
    },
  },
  {
    files: ["tests/**/*.ts"],
    rules: {
      "@typescript-eslint/no-non-null-assertion": "off",
    },
  }
);
