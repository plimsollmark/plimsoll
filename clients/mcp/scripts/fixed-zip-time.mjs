// Sets the time of every entry of a zip archive to 1980-01-01 00:00, the earliest a zip
// can state, in place. The bundle CLI stamps each entry with the time it ran, which is all
// that kept two builds of a bundle from being byte-identical; the compressed bytes and
// everything else are left as they are.
import { readFileSync, writeFileSync } from "node:fs";

const file = process.argv[2];
const zip = readFileSync(file);
const eocd = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
if (eocd < 0) throw new Error(`${file}: no end of central directory`);
const entries = zip.readUInt16LE(eocd + 10);
let at = zip.readUInt32LE(eocd + 16);
if (entries === 0xffff || at === 0xffffffff) throw new Error(`${file}: a ZIP64 archive, which this does not handle`);
for (let i = 0; i < entries; i++) {
  if (zip.readUInt32LE(at) !== 0x02014b50) throw new Error(`${file}: central directory entry ${i} is malformed`);
  const local = zip.readUInt32LE(at + 42);
  if (zip.readUInt32LE(local) !== 0x04034b50) throw new Error(`${file}: local header ${i} is malformed`);
  zip.writeUInt16LE(0, at + 12); // time
  zip.writeUInt16LE(0x21, at + 14); // date: 1980-01-01
  zip.writeUInt16LE(0, local + 10);
  zip.writeUInt16LE(0x21, local + 12);
  at += 46 + zip.readUInt16LE(at + 28) + zip.readUInt16LE(at + 30) + zip.readUInt16LE(at + 32);
}
writeFileSync(file, zip);
