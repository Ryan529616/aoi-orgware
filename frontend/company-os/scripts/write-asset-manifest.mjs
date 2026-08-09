import { createHash } from "node:crypto";
import { lstat, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../src/aoi_orgware/resources/dashboard_company_os"
);
const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"]
]);

function extension(path) {
  const index = path.lastIndexOf(".");
  return index < 0 ? "" : path.slice(index).toLowerCase();
}

async function walk(directory, prefix = "") {
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
  const files = [];
  for (const entry of entries) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (relative === "asset-manifest.json") continue;
    const path = resolve(directory, entry.name);
    const identity = await lstat(path);
    if (identity.isSymbolicLink() || (!identity.isDirectory() && !identity.isFile())) {
      throw new Error(`unsupported generated asset identity: ${relative}`);
    }
    if (identity.isDirectory()) {
      files.push(...await walk(path, relative));
      continue;
    }
    if (relative.includes("\\") || relative.split("/").some((part) => !/^[A-Za-z0-9._-]+$/.test(part))) {
      throw new Error(`unsafe generated asset path: ${relative}`);
    }
    const contentType = contentTypes.get(extension(relative));
    if (!contentType) throw new Error(`unsupported generated asset type: ${relative}`);
    const bytes = await readFile(path);
    files.push({
      path: relative,
      size_bytes: bytes.byteLength,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      content_type: contentType
    });
  }
  return files;
}

const files = await walk(root);
files.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
if (!files.some((entry) => entry.path === "index.html")) {
  throw new Error("generated Company OS assets do not include index.html");
}
const manifest = {
  schema_version: 1,
  frozen_v8_receipt_sha256: "3beba7750581c45e6e22213a04ea45771e0b43a0e2679cb6c200392d5b5063f0",
  files
};
await writeFile(
  resolve(root, "asset-manifest.json"),
  `${JSON.stringify(manifest)}\n`,
  { encoding: "utf8", flag: "w" }
);
