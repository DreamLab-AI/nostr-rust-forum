// R2 create-only conditional put: behavioural check under workerd/miniflare.
//
// `create_only_condition()` in src/lib.rs relies on R2 treating
// `onlyIf: { etagDoesNotMatch: "*" }` as a wildcard ("put only if absent").
// worker 0.8.5 serialises `Conditional` to exactly the object built below
// (four keys; `None` fields become `undefined`; see worker's r2/builder.rs).
// This script proves, against workerd's R2 implementation as shipped in
// miniflare, that a second create-only put is refused and leaves the first
// object intact, and (control) that a literal non-matching etag still writes,
// i.e. "*" is NOT compared literally.
//
// Not wired into CI (needs Node + miniflare). Run locally:
//   MINIFLARE_MODULE=/path/to/node_modules/miniflare/dist/src/index.js \
//     node crates/nostr-bbs-pod-worker/tests/r2_create_only.mjs
// Exits 0 on success, 1 on any mismatch.
const modulePath = process.env.MINIFLARE_MODULE ?? "miniflare";
const { Miniflare } = await import(modulePath);

const script = `export default { async fetch(req, env) {
  const cond = { etagMatches: undefined, etagDoesNotMatch: "*",
                 uploadedBefore: undefined, uploadedAfter: undefined };
  const first = await env.B.put("pods/x/inbox/msg", "first", { onlyIf: cond });
  const second = await env.B.put("pods/x/inbox/msg", "second", { onlyIf: cond });
  const stored = await (await env.B.get("pods/x/inbox/msg")).text();
  const literal = await env.B.put("pods/x/inbox/msg", "third",
                                  { onlyIf: { etagDoesNotMatch: "not-the-etag" } });
  return Response.json({ firstCreated: first !== null, secondCreated: second !== null,
                         stored, literalMismatchWrote: literal !== null });
}}`;

const mf = new Miniflare({ modules: true, script, r2Buckets: ["B"] });
try {
  const got = await (await mf.dispatchFetch("http://localhost/")).json();
  const want = { firstCreated: true, secondCreated: false, stored: "first", literalMismatchWrote: true };
  console.log(JSON.stringify(got));
  const ok = Object.entries(want).every(([k, v]) => got[k] === v);
  if (!ok) {
    console.error("MISMATCH: expected", JSON.stringify(want));
    process.exitCode = 1;
  } else {
    console.log("ok: create-only put refused on existing key; wildcard is not literal");
  }
} finally {
  await mf.dispose();
}
