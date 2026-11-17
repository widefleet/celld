const subtle = crypto.subtle;
const bytes = (hex) => Uint8Array.from(hex.match(/../g), (pair) => parseInt(pair, 16));
const hex = (data) =>
  Array.from(new Uint8Array(data), (byte) => byte.toString(16).padStart(2, "0")).join("");
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
const rejects = async (operation, name) => {
  try {
    await operation();
  } catch (error) {
    assert(error.name === name, `Expected ${name}, got ${error.name}`);
    return;
  }
  throw new Error(`Expected ${name}`);
};

export default {
  async fetch() {
    try {
      const raw = bytes("00112233445566778899aabbccddeeff");
      const key = await subtle.importKey("raw", raw, "AES-GCM", true, ["encrypt"]);
      for (const [length, expected] of [
        [128, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"],
        [192, "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"],
        [256, "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"],
      ]) {
        const material = Uint8Array.from({ length: length / 8 }, (_, index) => index);
        const wrapping = await subtle.importKey("raw", material, "AES-KW", false, [
          "wrapKey",
          "unwrapKey",
        ]);
        assert(wrapping.algorithm.length === length, "Incorrect key length");
        const wrapped = await subtle.wrapKey("raw", key, wrapping, "AES-KW");
        assert(hex(wrapped) === expected, "RFC 3394 wrap mismatch");
        const unwrapped = await subtle.unwrapKey(
          "raw",
          wrapped,
          wrapping,
          "AES-KW",
          "AES-GCM",
          true,
          ["encrypt"],
        );
        assert(hex(await subtle.exportKey("raw", unwrapped)) === hex(raw), "Unwrap mismatch");
        const modified = new Uint8Array(wrapped.slice(0));
        modified[0] ^= 1;
        await rejects(
          () => subtle.unwrapKey("raw", modified, wrapping, "AES-KW", "AES-GCM", true, ["encrypt"]),
          "OperationError",
        );
        const generated = await subtle.generateKey({ name: "AES-KW", length }, true, [
          "wrapKey",
          "unwrapKey",
        ]);
        assert(
          (await subtle.exportKey("raw", generated)).byteLength * 8 === length,
          "Generate length mismatch",
        );
        const again = await subtle.wrapKey("raw", key, generated, "AES-KW");
        const restored = await subtle.unwrapKey(
          "raw",
          again,
          generated,
          "AES-KW",
          "AES-GCM",
          true,
          ["encrypt"],
        );
        assert(
          hex(await subtle.exportKey("raw", restored)) === hex(raw),
          "Generated-key round trip mismatch",
        );
      }
      await rejects(
        () => subtle.importKey("raw", raw, "AES-KW", false, ["encrypt"]),
        "SyntaxError",
      );
      await rejects(() => subtle.importKey("raw", raw, "AES-KW", false, []), "SyntaxError");
      await rejects(
        () => subtle.importKey("raw", new Uint8Array(17), "AES-KW", false, ["wrapKey"]),
        "DataError",
      );
      await rejects(
        () => subtle.generateKey({ name: "AES-KW", length: 128 }, false, ["decrypt"]),
        "SyntaxError",
      );
      await rejects(
        () => subtle.generateKey({ name: "AES-KW", length: 0 }, false, ["wrapKey"]),
        "OperationError",
      );
      const unwrapOnly = await subtle.importKey("raw", raw, "AES-KW", false, ["unwrapKey"]);
      await rejects(() => subtle.wrapKey("raw", key, unwrapOnly, "AES-KW"), "InvalidAccessError");
      await rejects(() => subtle.wrapKey("raw", key, key, "AES-KW"), "InvalidAccessError");
      const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
        "sign",
        "verify",
      ]);
      const jwk = await subtle.exportKey("jwk", pair.publicKey);
      const jsonLength = new TextEncoder().encode(JSON.stringify(jwk)).byteLength;
      assert(jsonLength % 8 !== 0, "JWK fixture must require padding");
      const wrapping = await subtle.importKey("raw", raw, "AES-KW", false, [
        "wrapKey",
        "unwrapKey",
      ]);
      const wrappedJwk = await subtle.wrapKey("jwk", pair.publicKey, wrapping, "AES-KW");
      assert(
        wrappedJwk.byteLength === Math.ceil(jsonLength / 8) * 8 + 8,
        "JWK padding length mismatch",
      );
      const publicKey = await subtle.unwrapKey(
        "jwk",
        wrappedJwk,
        wrapping,
        "AES-KW",
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"],
      );
      const unwrappedJwk = await subtle.exportKey("jwk", publicKey);
      for (const field of ["kty", "crv", "x", "y"]) {
        assert(unwrappedJwk[field] === jwk[field], `JWK ${field} changed`);
      }
      const message = new TextEncoder().encode("Wrapped JWK round trip");
      const signature = await subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        message,
      );
      assert(
        await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, message),
        "Unwrapped JWK cannot verify",
      );
      return Response.json({ ok: true });
    } catch (error) {
      return new Response(error.stack ?? String(error), { status: 500 });
    }
  },
};
