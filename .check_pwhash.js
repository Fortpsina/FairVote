const fs = require("fs"); const vm = require("vm");
const { webcrypto } = require("crypto");
const ctx = { console, crypto: webcrypto }; ctx.window = ctx; ctx.self = ctx; ctx.globalThis = ctx;
vm.createContext(ctx);
const core = "D:/FairVote/.vendor-sumo/nm/libsodium-sumo@0.7.15/node_modules/libsodium-sumo/dist/modules-sumo/libsodium-sumo.js";
const wrap = "D:/FairVote/.vendor-sumo/nm/libsodium-wrappers-sumo@0.7.15/node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js";
vm.runInContext(fs.readFileSync(core, "utf8"), ctx, {filename:"core"});
vm.runInContext(fs.readFileSync(wrap, "utf8"), ctx, {filename:"wrap"});
(async () => {
  await ctx.sodium.ready;
  const result = await vm.runInContext(`(() => {
    const salt = new Uint8Array(16).fill(7);
    const out = sodium.crypto_pwhash(32, "correct horse battery staple", salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13);
    return { hex: sodium.to_hex(out), salt: sodium.crypto_pwhash_SALTBYTES,
             ops: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, mem: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE };
  })()`, ctx);
  console.log(JSON.stringify(result));
})().catch(e => { console.error("FAILED", e.message); process.exit(1); });
