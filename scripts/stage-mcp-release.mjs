import { copyFile, lstat, mkdir, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const MCP_RELEASE_FILES = [
  "index.js",
  "challenge.js",
  "challenge.test.js",
  "contract.test.js",
  "fixtures/v0.1.28-tools.json",
  "safe-open-lifecycle.js",
  "safe-open-lifecycle.test.js",
  "verification-checkpoint.js",
  "verification-checkpoint.test.js",
  "package.json",
  "package-lock.json",
  "README.md",
];

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDir, "..");
const sourceRoot = path.join(repositoryRoot, "mcp");

function manifestTreeEntries() {
  const directories = new Set();
  for (const file of MCP_RELEASE_FILES) {
    const parts = file.split("/");
    for (let index = 1; index < parts.length; index += 1) {
      directories.add(`${parts.slice(0, index).join("/")}/`);
    }
  }
  return [...directories, ...MCP_RELEASE_FILES];
}

function assertArchiveRoot(archiveRoot) {
  if (
    typeof archiveRoot !== "string" ||
    archiveRoot === "." ||
    archiveRoot === ".." ||
    !/^[A-Za-z0-9._-]+$/.test(archiveRoot)
  ) {
    throw new Error("archive root must be one safe path segment");
  }
}

function assertExactEntries(actualEntries, expectedEntries, label) {
  const duplicates = actualEntries.filter(
    (entry, index) => actualEntries.indexOf(entry) !== index,
  );
  if (duplicates.length) {
    throw new Error(`duplicate archive entry: ${[...new Set(duplicates)].join(", ")}`);
  }

  const actual = new Set(actualEntries);
  const expected = new Set(expectedEntries);
  const missing = expectedEntries.filter((entry) => !actual.has(entry));
  const extra = actualEntries.filter((entry) => !expected.has(entry));
  if (missing.length || extra.length || actualEntries.length !== expectedEntries.length) {
    throw new Error(
      `${label} archive manifest mismatch: missing=[${missing.join(", ")}] extra=[${extra.join(", ")}]`,
    );
  }
}

export function expectedArchiveEntries(archiveRoot = "ShardX-MCP") {
  assertArchiveRoot(archiveRoot);
  return [
    `${archiveRoot}/`,
    ...manifestTreeEntries().map((entry) => `${archiveRoot}/${entry}`),
  ];
}

export function verifyArchiveEntries(actualEntries, archiveRoot = "ShardX-MCP") {
  const normalized = actualEntries.map((entry) =>
    typeof entry === "string" ? entry.replace(/\r$/, "") : entry,
  );
  assertExactEntries(normalized, expectedArchiveEntries(archiveRoot), "MCP");
}

async function directoryEntries(root, relative = "") {
  const entries = [];
  const children = await readdir(path.join(root, relative), { withFileTypes: true });
  children.sort((left, right) => left.name.localeCompare(right.name));
  for (const child of children) {
    const childRelative = relative
      ? `${relative.replaceAll(path.sep, "/")}/${child.name}`
      : child.name;
    if (child.isDirectory()) {
      entries.push(`${childRelative}/`);
      entries.push(...(await directoryEntries(root, childRelative)));
    } else {
      entries.push(childRelative);
    }
  }
  return entries;
}

export async function verifyReleaseDirectory(targetRoot) {
  const actualEntries = await directoryEntries(targetRoot);
  assertExactEntries(actualEntries, manifestTreeEntries(), "MCP");
  for (const file of MCP_RELEASE_FILES) {
    const metadata = await lstat(path.join(targetRoot, file));
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`MCP release entry must be a regular file: ${file}`);
    }
  }
}

export async function stageRelease(targetRoot) {
  await mkdir(targetRoot, { recursive: true });
  const existing = await readdir(targetRoot);
  if (existing.length) {
    throw new Error(`MCP release destination must be empty: ${targetRoot}`);
  }
  for (const file of MCP_RELEASE_FILES) {
    const source = path.join(sourceRoot, file);
    await stat(source);
    await mkdir(path.dirname(path.join(targetRoot, file)), { recursive: true });
    await copyFile(source, path.join(targetRoot, file));
  }
  await verifyReleaseDirectory(targetRoot);
}

async function readStandardInput() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function parseEntryList(raw) {
  const entries = raw.split(/\n/);
  while (entries.at(-1) === "") {
    entries.pop();
  }
  return entries;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const [command, value] = args;
  const usage =
    "usage: node scripts/stage-mcp-release.mjs <target-directory>|--list|--verify-directory <directory>|--verify-archive-entries [archive-root]";
  if (command === "--list" && args.length === 1) {
    process.stdout.write(`${MCP_RELEASE_FILES.join("\n")}\n`);
  } else if (command === "--verify-directory" && value && args.length === 2) {
    await verifyReleaseDirectory(path.resolve(value));
  } else if (command === "--verify-archive-entries" && args.length <= 2) {
    const archiveRoot = value || "ShardX-MCP";
    verifyArchiveEntries(parseEntryList(await readStandardInput()), archiveRoot);
  } else if (command && !command.startsWith("--") && args.length === 1) {
    await stageRelease(path.resolve(command));
  } else {
    throw new Error(usage);
  }
}
