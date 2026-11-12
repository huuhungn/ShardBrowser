#!/usr/bin/env node
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  args.set(process.argv[i], process.argv[i + 1]);
}

const dist = args.get("--dist") ?? "dist";
const tag = args.get("--tag");
const repo = args.get("--repo") ?? process.env.GITHUB_REPOSITORY;
if (!tag || !repo) {
  throw new Error(
    "Usage: generate-updater-manifest.mjs --dist dist --tag vX.Y.Z --repo owner/repo",
  );
}

const files = readdirSync(dist).sort((left, right) => left.localeCompare(right));
const unsafeAsset = files.find((name) => !/^[A-Za-z0-9._-]+$/.test(name));
if (unsafeAsset) {
  throw new Error(
    `Release asset name must already be GitHub-safe before manifest generation: ${unsafeAsset}`,
  );
}
const baseUrl = `https://github.com/${repo}/releases/download/${tag}`;
const version = tag.replace(/^v/, "");

const targets = {
  "windows-x86_64": {
    description: "one NSIS setup executable",
    matches: (name) => /setup\.exe$/i.test(name),
  },
  "linux-x86_64": {
    description: "one x86_64 AppImage",
    matches: (name) => /\.AppImage$/.test(name),
  },
};

const platforms = {};
for (const [platform, policy] of Object.entries(targets)) {
  const matches = files.filter(policy.matches);
  if (matches.length !== 1) {
    throw new Error(
      `Expected ${policy.description} for ${platform}, found ${matches.length}: ${matches.join(", ") || "none"}`,
    );
  }
  const [asset] = matches;

  const sig = `${asset}.sig`;
  if (!files.includes(sig)) {
    throw new Error(`Missing updater signature ${sig} for ${asset}.`);
  }

  const signature = readFileSync(join(dist, sig), "utf8").trim();
  if (!signature) {
    throw new Error(`Updater signature ${sig} is empty.`);
  }

  platforms[platform] = {
    signature,
    url: `${baseUrl}/${encodeURIComponent(basename(asset))}`,
  };
}

writeFileSync(
  join(dist, "latest.json"),
  `${JSON.stringify(
    {
      version,
      notes: `ShardX Launcher ${tag}`,
      pub_date: new Date().toISOString(),
      platforms,
    },
    null,
    2,
  )}\n`,
);
