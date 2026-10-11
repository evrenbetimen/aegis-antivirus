// .pkg test örnekleri üreticisi (xar + cpio) — installer.test.js ve e2e-scan.js
const zlib = require('zlib');

function cpioOdc(entries) {
  const parts = [];
  const oct = (n, w) => n.toString(8).padStart(w, '0');
  for (const e of entries.concat([{ name: 'TRAILER!!!', data: '', mode: 0 }])) {
    const data = Buffer.from(e.data);
    const name = Buffer.from(e.name + '\0');
    const mode = e.mode === undefined ? 0o100644 : e.mode;
    const h =
      '070707' + oct(0, 6) + oct(1, 6) + oct(mode, 6) + oct(0, 6) + oct(0, 6) + oct(1, 6) + oct(0, 6) +
      oct(0, 11) + oct(name.length, 6) + oct(data.length, 11);
    parts.push(Buffer.from(h, 'latin1'), name, data);
  }
  return Buffer.concat(parts);
}

function cpioNewc(entries) {
  const parts = [];
  const hex = (n) => n.toString(16).padStart(8, '0');
  for (const e of entries.concat([{ name: 'TRAILER!!!', data: '', mode: 0 }])) {
    const data = Buffer.from(e.data);
    const name = Buffer.from(e.name + '\0');
    const mode = e.mode === undefined ? 0o100755 : e.mode;
    const fields = [1, mode, 0, 0, 1, 0, data.length, 0, 0, 0, 0, name.length, 0];
    const h = Buffer.from('070701' + fields.map(hex).join(''), 'latin1');
    parts.push(h, name, Buffer.alloc((4 - ((110 + name.length) % 4)) % 4));
    parts.push(data, Buffer.alloc((4 - (data.length % 4)) % 4));
  }
  return Buffer.concat(parts);
}

/**
 * Asgari xar üretir. files: [{ path:'a/b', data:Buffer, zlib?:bool }]
 * Ara dizinler <file><type>directory</type> olarak eklenir.
 */
function makeXar(files) {
  const heap = [];
  let off = 0;
  const root = { children: new Map() };
  for (const f of files) {
    const segs = f.path.split('/');
    let node = root;
    for (let i = 0; i < segs.length; i++) {
      if (!node.children.has(segs[i])) node.children.set(segs[i], { children: new Map() });
      node = node.children.get(segs[i]);
    }
    const stored = f.zlib ? zlib.deflateSync(f.data) : f.data;
    node.file = { offset: off, length: stored.length, size: f.data.length, zlib: !!f.zlib };
    heap.push(stored);
    off += stored.length;
  }
  let id = 0;
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
  const emit = (name, node) => {
    id++;
    if (node.file) {
      const enc = node.file.zlib ? 'application/x-gzip' : 'application/octet-stream';
      return (
        `<file id="${id}"><data><length>${node.file.length}</length><offset>${node.file.offset}</offset>` +
        `<size>${node.file.size}</size><encoding style="${enc}"/></data><name>${esc(name)}</name><type>file</type></file>`
      );
    }
    const kids = [...node.children].map(([n, c]) => emit(n, c)).join('');
    return `<file id="${id}"><name>${esc(name)}</name><type>directory</type>${kids}</file>`;
  };
  const body = [...root.children].map(([n, c]) => emit(n, c)).join('');
  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<xar><toc><creation-time>x</creation-time>${body}</toc></xar>`;
  const toc = zlib.deflateSync(Buffer.from(xml));
  const h = Buffer.alloc(28);
  h.write('xar!', 0, 'latin1');
  h.writeUInt16BE(28, 4);
  h.writeUInt16BE(1, 6);
  h.writeBigUInt64BE(BigInt(toc.length), 8);
  h.writeBigUInt64BE(BigInt(xml.length), 16);
  h.writeUInt32BE(0, 24);
  return Buffer.concat([h, toc, ...heap]);
}

module.exports = { cpioOdc, cpioNewc, makeXar };
