// A thin domain SDK layered on plimsoll's generic host.* client.
//
// A grant injects `host` (call/get/put/post/patch/del) into the run. That surface is
// deliberately generic, so agent code written against it reads as HTTP plumbing:
//
//     const item = await host.get("/v1/items/" + id);
//
// A profile's `preamble_file` lets an embedder load a small module like this one on
// top, so the same call reads as the domain instead:
//
//     const item = await inventory.items.get(id);
//
// The preamble is a convenience, never a boundary. It runs inside the sandbox, so
// hostile code can ignore it and call `host` directly, or bypass `host` and call the
// raw bridge. Route enforcement and the credential both live host-side in the shared
// broker, which is what makes that harmless. See examples/grant for a demonstration
// of exactly that bypass being refused.
globalThis.inventory = (function () {
  // Reject ids that would change path segmentation or split off a query or fragment.
  // The broker independently rejects non-canonical and ungranted targets, so this
  // check buys a clearer error message and nothing else. Do not mistake it for the
  // control: if you delete it, the boundary is unchanged.
  function segment(value, label) {
    const s = String(value);
    if (s === "" || s.indexOf("/") >= 0 || s.indexOf("?") >= 0 || s.indexOf("#") >= 0) {
      throw new Error("inventory: invalid " + label + ": " + s);
    }
    return s;
  }

  return {
    // Methods are async because every provider's host client returns a Promise.
    // Always await; a forgotten await is the most common way one of these reads as
    // "undefined" rather than as an error.
    items: {
      get: (id) => host.get("/v1/items/" + segment(id, "item id")),
      counts: (id) => host.get("/v1/items/" + segment(id, "item id") + "/counts"),
      adjust: (id, body) => host.post("/v1/items/" + segment(id, "item id") + "/adjust", body),
    },
    warehouses: {
      list: () => host.get("/v1/warehouses"),
      items: (id) => host.get("/v1/warehouses/" + segment(id, "warehouse id") + "/items"),
    },
    ping: () => host.post("/ping", {}),
  };
})();
