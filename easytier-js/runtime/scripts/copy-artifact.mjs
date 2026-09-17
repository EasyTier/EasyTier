import { copyFile, mkdir } from "node:fs/promises";
import path from "node:path";

const [sourceArgument, destinationArgument] = process.argv.slice(2);
if (sourceArgument === undefined || destinationArgument === undefined) {
  throw new Error("usage: copy-artifact.mjs <source> <destination>");
}

const source = path.resolve(process.cwd(), sourceArgument);
const destination = path.resolve(process.cwd(), destinationArgument);
await mkdir(path.dirname(destination), { recursive: true });
await copyFile(source, destination);
