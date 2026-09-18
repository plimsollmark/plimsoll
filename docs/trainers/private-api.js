(() => {
  "use strict";

  const byId = (id) => document.getElementById(id);

  const processFacts = {
    model: {
      label: "LLM model",
      source: "The LLM is usually hosted by the caller's agent product, not by Stockroom. It receives the MCP host's tool definitions and chooses whether to emit a tool call.",
      input: "Tool descriptions, input schemas, and the MCP resource summary in its context.",
      output: "A model message such as tools/call run_javascript with a JSON argument object.",
      boundary: "It does not receive the private bearer, the gateway's BaseURL, or a raw /v1/warehouses HTTP client.",
      links: []
    },
    mcp: {
      label: "MCP client / host",
      source: "A host process such as an IDE, agent runtime, or desktop app owns the MCP connection. Stockroom supports Streamable HTTP at POST /mcp and a separate stdio entrypoint.",
      input: "Model tool selection plus arguments.",
      output: "MCP JSON-RPC tools/call to the gateway, or stdio frames to the local server.",
      boundary: "It is the protocol bridge. It does not become the private API credential holder.",
      links: [
        {href: "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports", label: "MCP transport specification", external: true},
        {href: "https://ts.sdk.modelcontextprotocol.io/server", label: "MCP TypeScript server API", external: true}
      ]
    },
    gateway: {
      label: "Stockroom gateway",
      source: "The Stockroom Node process owns the HTTP routes, MCP server, tool handlers, and Connect clients. Its HTTP layer uses <a class=\"inline-reference external-reference\" href=\"https://hono.dev/docs\" target=\"_blank\" rel=\"noopener\">Hono</a>, a small Web Standards web framework.",
      input: "POST /mcp JSON-RPC, or a private REST request such as GET /v1/warehouses.",
      output: "For direct tools, a StockService Connect call. For code mode, codegenClient.runJavaScript().",
      boundary: "It presents and forwards. Go dataplane auth and per-RPC policy remain authoritative.",
      links: [
        {href: "https://ts.sdk.modelcontextprotocol.io/server", label: "MCP TypeScript server API", external: true},
        {href: "agent-products.html", label: "MCP product trainer"}
      ]
    },
    dataplane: {
      label: "Stockroom Go dataplane",
      source: "The Stockroom Go process listens on DATAPLANE_ADDR, usually :8746, and registers StockService plus CodegenService.",
      input: "Authenticated Connect RPC from the gateway, with the caller principal forwarded by the interceptor.",
      output: "Stock calls to the backend, or a validated sandbox.Request to a local provider or remote plimsoll client.",
      boundary: "This is where Stockroom owns execution admission, authentication, scope checks, and its snippet grant setup.",
      links: [
        {href: "https://connectrpc.com/", label: "Connect RPC overview", external: true},
        {href: "https://grpc.io/docs/what-is-grpc/core-concepts/", label: "gRPC core concepts", external: true},
        {href: "https://protobuf.dev/overview/", label: "Protocol Buffers overview", external: true}
      ]
    },
    runner: {
      label: "plimsoll / plimsolld",
      source: "The plimsoll Go sandbox package is embedded locally or reached through plimsolld's versioned Connect API.",
      input: "A Run request with a javascript payload, or an in-process sandbox.Request, including a named server-side grant profile in remote mode.",
      output: "A result with stdout, stderr, exit status, isolation evidence, and optional metadata-only advice.",
      boundary: "The broker owns the BaseURL, allowlist match, minted credential, transport, and call budgets.",
      links: [
        {href: "brokering.html", label: "API broker trainer"},
        {href: "capabilities.html", label: "Capability grant trainer"}
      ]
    },
    guest: {
      label: "Guest JavaScript",
      source: "Untrusted agent-authored code runs in Node inside the configured Docker provider, or in QuickJS inside the WASM provider.",
      input: "The code string and a deliberately tiny injected runtime surface.",
      output: "host.get/put calls framed to the broker, then ordinary stdout/stderr and an exit code.",
      boundary: "No bearer, no private origin, no host filesystem, and no ambient network. inventory.* and host.* are globals, not MCP tools.",
      links: [
        {href: "brokering.html", label: "API broker trainer"},
        {href: "capabilities.html", label: "Capability grant trainer"}
      ]
    },
    private: {
      label: "Gateway private REST route",
      source: "GET /v1/warehouses is a <a class=\"inline-reference external-reference\" href=\"https://hono.dev/docs\" target=\"_blank\" rel=\"noopener\">Hono</a> HTTP route inside the existing Node gateway process. It is a layer, not another Stockroom process.",
      input: "A brokered HTTP request from plimsoll, including the server-side Authorization header.",
      output: "stockClient.listWarehouses({}), then a Connect/gRPC request to Go StockService.",
      boundary: "It is private because the model is not given this route as a general network surface.",
      links: [
        {href: "brokering.html", label: "API broker trainer"},
        {href: "capabilities.html", label: "Capability grant trainer"}
      ]
    },
    external: {
      label: "WMS / ERP system",
      source: "The external system of record sits outside the Stockroom and plimsoll process boundaries. Go's provider client talks to it directly.",
      input: "Provider-specific stock requests from the Go dataplane.",
      output: "Warehouse, item, count, or adjustment data back to the Go StockService.",
      boundary: "This is not MCP, not Connect/gRPC, and not a plimsoll guest. It is the actual system of record.",
      links: [
        {href: "https://grpc.io/docs/what-is-grpc/core-concepts/", label: "gRPC core concepts", external: true},
        {href: "https://protobuf.dev/overview/", label: "Protocol Buffers overview", external: true}
      ]
    }
  };

  const directTrace = [
    {
      process: ["model"], title: "The model chooses a direct tool", actor: "LLM model",
      body: "The MCP context contains list_warehouses as a normal typed tool. The model asks for it; no JavaScript is authored and no sandbox is started.",
      wire: '{"method":"tools/call","params":{"name":"list_warehouses","arguments":{}}}',
      boundary: "The model can request the registered operation. It cannot invent a new private route.", tag: "model emits"
    },
    {
      process: ["mcp"], title: "The MCP host sends JSON-RPC", actor: "MCP client / host",
      body: "The host puts the model's tool call on its Stockroom MCP connection. For a remote server this is POST /mcp; for a local integration it may be a stdio frame.",
      wire: 'POST /mcp\n\n{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"list_warehouses","arguments":{}}}',
      boundary: "MCP is the model-facing protocol. It is not the private REST API itself.", tag: "mcp wire"
    },
    {
      process: ["gateway"], title: "The gateway dispatches list_warehouses", actor: "Stockroom gateway",
      body: "The Node gateway's McpServer finds the registered tool and runs its handler. The direct handler calls stockClient.listWarehouses({}), not plimsoll.",
      wire: "registerTools()\n  list_warehouses handler\n    → stockClient.listWarehouses({})",
      boundary: "This path bypasses CodegenService, plimsoll, the guest, and the private REST /v1/warehouses route.", tag: "handler call"
    },
    {
      process: ["dataplane"], title: "Connect crosses to the Go dataplane", actor: "Stockroom dataplane",
      body: "The gateway's generated Connect client sends StockService/ListWarehouses to the Go process on :8746. The auth interceptor forwards the caller token; Go enforces the RPC scope.",
      wire: "Connect RPC\nStockService/ListWarehouses\nAuthorization: Bearer <caller token>",
      boundary: "The dataplane owns the stock operation and its authorization decision.", tag: "connect rpc"
    },
    {
      process: ["dataplane"], title: "Go StockService calls its provider client", actor: "Stockroom dataplane",
      body: "The Go handler receives StockService/ListWarehouses and calls its internal WMS client. The dataplane owns this domain-to-provider translation; the Node gateway does not.",
      wire: "StockService/ListWarehouses\n→ internal/wms.Client.ListWarehouses()\n→ vendor HTTP(S)",
      boundary: "The dataplane calls the stock provider directly. It does not call the gateway to reach the WMS or ERP.", tag: "provider call"
    },
    {
      process: ["external"], title: "The external system of record answers", actor: "WMS / ERP system",
      body: "The provider outside Stockroom returns the stock data to Go. The response then travels back through StockService, the gateway MCP handler, and the MCP host to the model.",
      wire: "vendor HTTP(S) response\n→ StockService/ListWarehouses response\n→ MCP structuredContent + text",
      boundary: "This is an external service, not an MCP server, Connect server, plimsoll process, or guest runtime.", tag: "result returns"
    }
  ];

  const codeTrace = (deployment) => {
    const runner = deployment === "remote" ? {
      process: ["runner"], title: "The remote runner receives versioned RPC", actor: "plimsolld",
      body: "The Go dataplane's remote client calls plimsolld's one procedure, Run, with a javascript payload inside a protocol-numbered envelope. It selects a server-side grant_profile; it does not send a raw BaseURL or token from the caller.",
      wire: "Connect RPC\nplimsoll.v1.SandboxService/Run\nprotocol: 1\njavascript: { code, grant_profile: stockroom }",
      boundary: "A remote hop adds process separation. plimsolld still validates the request and owns the grant registry.", tag: "remote hop"
    } : {
      process: ["runner"], title: "The dataplane enters a local provider", actor: "plimsoll in-process",
      body: "The Go dataplane calls the configured sandbox provider directly. With Docker, plimsoll starts a locked-down guest container and a per-run Unix broker socket.",
      wire: "sandbox.Request{Code, Timeout, Grant}\n→ Docker provider\n→ per-run host-api.sock",
      boundary: "The provider boundary and the broker boundary are separate decisions. A local provider is not permission to run native host code.", tag: "local provider"
    };
    return [
      {
        process: ["model"], title: "The model sees a code tool", actor: "LLM model",
        body: "The model is told that run_javascript exists. Its input schema is just code and timeoutMs; the injected inventory.* surface is explained by the description and the sandbox API resource.",
        wire: '{"method":"tools/call","params":{"name":"run_javascript","arguments":{"code":"const w = await inventory.warehouses.list();\\nconsole.log(w)","timeoutMs":20000}}}',
        boundary: "The model sees a tool contract and examples. It does not see the private API token or a general fetch credential.", tag: "model emits"
      },
      {
        process: ["mcp"], title: "The MCP host forwards run_javascript", actor: "MCP client / host",
        body: "The MCP host sends the tool call to the Node gateway. This is the only moment the model-facing tool protocol carries the code string.",
        wire: "POST /mcp\nJSON-RPC tools/call\nname: run_javascript\narguments: { code, timeoutMs }",
        boundary: "MCP carries code as an argument. MCP does not execute it and does not expose inventory.* as a second set of MCP tools.", tag: "mcp wire"
      },
      {
        process: ["gateway"], title: "The Node tool handler calls codegenClient", actor: "Stockroom gateway",
        body: "registerTools() invokes the run_javascript handler. That handler calls codegen.runJavaScript(), which is a generated Connect client for CodegenService.",
        wire: "run_javascript handler\n  → codegenClient.runJavaScript({ code, timeoutMs })",
        boundary: "The gateway is a forwarding and presentation layer. It does not put the private bearer in the code string.", tag: "handler call"
      },
      {
        process: ["dataplane"], title: "Go CodegenService creates the request", actor: "Stockroom dataplane",
        body: "CodegenService validates the request, applies the caller principal when subject-bound grants are configured, acquires its limiter, and calls the sandbox.",
        wire: "Connect RPC\nCodegenService/RunJavaScript\nAuthorization: Bearer <caller token>\n→ sandbox.Request{Grant: SnippetGrant}",
        boundary: "The Go service owns the execution admission decision. A failed validation or insufficient isolation means guest code did not run.", tag: "execution gate"
      },
      runner,
      {
        process: ["guest"], title: "The isolated guest runs the SDK call", actor: "Guest JavaScript",
        body: "The preamble creates inventory.warehouses.list(). The function becomes a generic host call. In Docker, the guest frames it over the Unix socket; in WASM, it crosses a bounded wazero host function.",
        wire: "guest code: await inventory.warehouses.list()\nSDK preamble: host.get(\"/v1/warehouses\")\ncredential: not present",
        boundary: "This is where plimsoll earns its keep: useful code composition without ambient HTTP, host filesystem, or a readable token.", tag: "guest starts"
      },
      {
        process: ["runner"], title: "The broker makes the private call", actor: "plimsoll broker",
        body: "The shared broker matches GET /v1/warehouses against the Stockroom allowlist, checks the canonical wire target, mints or retrieves the per-run credential outside the guest, and sends the request.",
        wire: "approve: GET /v1/warehouses\nwire:    GET /v1/warehouses\nAuthorization: Bearer <run token>",
        boundary: "The guest supplied only method, path, and bounded body. The broker supplied origin, credential, route enforcement, and budget.", tag: "broker egress"
      },
      {
        process: ["private", "gateway"], title: "The Node gateway route receives it", actor: "Stockroom gateway",
        body: "The broker's HTTP request reaches GET /v1/warehouses, a route in the same Node process that served /mcp. The route calls stockClient.listWarehouses({}).",
        wire: "GET /v1/warehouses\npeer: plimsoll broker\n→ stockClient.listWarehouses({})",
        boundary: "This is a route layer, not a separate process. The model was never given this route as general network access.", tag: "private REST"
      },
      {
        process: ["dataplane"], title: "The Go StockService handles the route", actor: "Stockroom dataplane",
        body: "The gateway's generated client sends StockService/ListWarehouses over Connect/gRPC. Go receives it, then calls the internal the WMS or ERP provider client.",
        wire: "Connect/gRPC\nStockService/ListWarehouses\n→ internal provider client\n→ vendor HTTP(S)",
        boundary: "The dataplane is both the recipient of the gateway RPC and the owner of the provider call. It does not call the gateway back for this step.", tag: "stock RPC"
      },
      {
        process: ["external"], title: "WMS / ERP returns stock data", actor: "External system of record",
        body: "The external provider answers the Go dataplane. The typed StockService response then returns to the Node gateway, to plimsoll, and into the guest.",
        wire: "vendor HTTP(S) response\n→ StockService/ListWarehouses\n→ gateway /v1/warehouses response",
        boundary: "This external API is outside the Stockroom and plimsoll process boundaries.", tag: "provider result"
      },
      {
        process: ["guest", "runner"], title: "The result returns as data, not a new capability", actor: "Guest + plimsoll result",
        body: "The response body is bounded and returned to the guest. The guest prints a summary; CodegenService returns stdout and status to the gateway's MCP adapter.",
        wire: "private API response\n→ host.get result\n→ console.log\n→ RunJavaScriptResponse{stdout, exit_code}",
        boundary: "The response is useful data for this run. It does not reveal the token, grant registry, or a new network route.", tag: "result returns"
      },
      {
        process: ["gateway", "mcp", "model"], title: "MCP returns the final tool result", actor: "Gateway → MCP host → model",
        body: "The gateway sanitizes the result into MCP content text and structuredContent. The host places it back in the model's context so the model can explain what it found.",
        wire: "RunJavaScriptResponse\n→ MCP content + structuredContent\n→ model context",
        boundary: "The model learns the result of a controlled computation, not the internal process graph or a reusable credential.", tag: "trace complete"
      }
    ];
  };

  const exposureCopy = {
    model: {
      title: "The model gets a tool contract, not a private API connection",
      intro: "This is the material the MCP host can put into model context. Notice that /v1/warehouses is absent from the model-facing tool schema.",
      code: `tools/list →\n\n{\n  "name": "run_javascript",\n  "description": "Stockroom · code sandbox ...",\n  "inputSchema": {\n    "type": "object",\n    "properties": { "code": { "type": "string" },\n                    "timeoutMs": { "type": "number" } }\n  },\n  "_meta": {\n    "stockroom/sandboxApi": {\n      "globals": ["inventory", "host"],\n      "discover": "inventory.describe()",\n      "resource": "stockroom://sandbox-api.d.ts"\n    }\n  }\n}`,
      note: "The description teaches the model how to write code. The resource supplies the TypeScript declarations. Neither is a bearer token, and neither turns the private REST surface into arbitrary model authority."
    },
    mcp: {
      title: "The MCP wire carries a tool call",
      intro: "The gateway's Streamable HTTP endpoint receives JSON-RPC. The stdio entrypoint uses the same buildMcpServer() and the same tool registry, but a different transport.",
      code: `POST /mcp\n\n{"jsonrpc":"2.0","id":42,\n "method":"tools/call",\n "params":{\n   "name":"run_javascript",\n   "arguments":{\n     "code":"const x = await inventory.warehouses.list();\\nconsole.log(x)"\n   }\n }}`,
      note: "The MCP client or host is the caller of the gateway's MCP server. It is not the caller of /v1/warehouses. The private API hop happens later, after CodegenService and plimsoll have made it safe."
    },
    guest: {
      title: "The guest gets globals, not MCP tools",
      intro: "Inside the isolated runtime, the model-authored code sees the typed Stockroom SDK preamble and the generic host client. These names are injected at runtime and are not network sockets.",
      code: `// guest process: Node in Docker, or QuickJS in WASM\nconst warehouses = await inventory.warehouses.list();\nconst short = warehouses.filter(w => w.belowReorderPoint > 0);\nconsole.log(JSON.stringify({ count: short.length }));\n\n// beneath the SDK helper:\nhost.get("/v1/warehouses");\n// token: not in this process\n// network: not ambient`,
      note: "inventory.* is the domain-friendly layer. host.* is the generic capability layer. Both delegate to plimsoll's broker, and neither can choose a new BaseURL."
    },
    api: {
      title: "The route and the processes behind it",
      intro: "In code mode, plimsoll reaches a REST route inside the Node gateway. That route then uses Connect/gRPC to the Go dataplane, which calls the WMS or ERP directly.",
      code: `GET /v1/warehouses HTTP/1.1\nHost: stockroom-gateway\nAuthorization: Bearer <short-lived run token>\n\nNode gateway route:\n  stockClient.listWarehouses({})\n    │ Connect/gRPC\n    ▼\nGo StockService:\n  internal/wms.Client.ListWarehouses()\n    │ vendor HTTP(S)\n    ▼\nWMS / ERP`,
      note: "The route is not a process. The Node gateway and Go dataplane are the Stockroom processes; the WMS or ERP is external. In direct MCP mode, list_warehouses calls StockService directly and skips this private REST hop."
    }
  };

  const directExposureCopy = {
    model: {
      title: "The model gets one direct stock tool",
      intro: "The direct path exposes a normal MCP operation. There is no run_javascript description because the model did not ask for code mode.",
      code: `tools/list →\n\n{\n  "name": "list_warehouses",\n  "description": "Stockroom · list warehouses ...",\n  "inputSchema": {\n    "type": "object",\n    "properties": {}\n  },\n  "outputSchema": {\n    "type": "object"\n  }\n}`,
      note: "The model can request the registered stock operation. It cannot turn that operation into a general private API client, and it never starts a guest process."
    },
    mcp: {
      title: "The MCP wire names list_warehouses directly",
      intro: "The host sends the same JSON-RPC shape, but the tool name selects a gateway handler that calls StockService rather than CodegenService.",
      code: `POST /mcp\n\n{"jsonrpc":"2.0","id":7,\n "method":"tools/call",\n "params":{\n   "name":"list_warehouses",\n   "arguments":{}\n }}`,
      note: "There is no code string in this message. No sandbox request exists downstream, so plimsoll has no role in the direct path."
    },
    guest: {
      title: "No guest runtime exists",
      intro: "Direct MCP is a typed one-shot operation. The request goes from the gateway's tool handler to the Go StockService.",
      code: `guest process: none\n\nno inventory.* global\nno host.* global\nno sandbox.Request\nno plimsoll broker hop`,
      note: "This is the simplest path when the operation already has a useful MCP tool. Code mode is for composition, not a mandatory detour."
    },
    api: {
      title: "The Go stock service receives the direct call",
      intro: "The direct handler uses the gateway's Connect client, so it does not call the gateway's own private REST /v1/warehouses route.",
      code: `gateway handler:\nstockClient.listWarehouses({})\n\nConnect RPC:\nStockService/ListWarehouses\n→ WMS / ERP`,
      note: "Same stock data, shorter process graph. The private REST route is still available for the brokered code-mode path, but this direct tool does not need it."
    }
  };

  const protocolCopy = {
    "mcp-http": {
      label: "MCP OVER HTTP",
      title: "Streamable HTTP carries JSON-RPC to the Node gateway",
      from: "MCP client / host → Stockroom gateway /mcp",
      intro: "MCP is the model-facing application protocol. JSON-RPC supplies the envelope: jsonrpc identifies the version, id lets the host match the response, method names the operation, and params carries the tool name and arguments.",
      code: `POST /mcp HTTP/1.1\nAuthorization: Bearer <caller token>\nContent-Type: application/json\n\n{"jsonrpc":"2.0","id":42,\n "method":"tools/call",\n "params":{\n   "name":"run_javascript",\n   "arguments":{"code":"await inventory.warehouses.list()"}\n }}\n\n← {"jsonrpc":"2.0","id":42,\n   "result":{"content":[{"type":"text","text":"..."}]}}`,
      note: "The gateway authenticates the edge request, creates a stateless MCP transport, builds the shared tool registry, and forwards the request to the registered handler. It logs the method and tool name, never the body. This hop does not execute JavaScript and does not call /v1/warehouses directly.",
      links: [
        {href: "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports", label: "MCP transport specification", external: true},
        {href: "https://www.jsonrpc.org/specification", label: "JSON-RPC 2.0 specification", external: true},
        {href: "https://ts.sdk.modelcontextprotocol.io/server", label: "MCP TypeScript server API", external: true}
      ]
    },
    "mcp-stdio": {
      label: "MCP OVER STDIO",
      title: "stdio is a local process connection, not HTTP",
      from: "MCP host → local gateway MCP child process",
      intro: "A host such as an IDE or desktop agent can launch the Stockroom MCP entrypoint as a child process. The host writes MCP JSON-RPC messages to the child's standard input and reads JSON-RPC responses from its standard output.",
      code: `MCP host process\n  spawn: Stockroom MCP server\n  stdin  ── JSON-RPC tools/list ──→\n  stdout ← JSON-RPC tools/list result ←\n\nThe child creates:\n  new StdioServerTransport()\n  shared MCP server + tool handlers\n\nNo POST /mcp. No gateway HTTP listener.\nThe tool definitions and handlers are otherwise the same.`,
      note: "stdio is a transport, not a different tool API. The local entrypoint and the remote /mcp route share buildMcpServer(), so both expose list_warehouses and run_javascript. The host owns the child-process lifecycle.",
      links: [
        {href: "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports", label: "MCP transport specification", external: true},
        {href: "https://ts.sdk.modelcontextprotocol.io/server", label: "MCP TypeScript server API", external: true},
        {href: "https://www.jsonrpc.org/specification", label: "JSON-RPC 2.0 specification", external: true}
      ]
    },
    connect: {
      label: "CONNECT / gRPC",
      title: "Typed RPC carries protobuf messages to Go",
      from: "Node gateway → Stockroom Go dataplane :8746",
      intro: "Connect is the RPC layer generated from a .proto service definition. In this project the gateway uses createGrpcTransport, so the normal hop is gRPC over HTTP/2 with a typed protobuf request. The Go server also exposes gRPC-Web and Connect/JSON on the same handler.",
      code: `HTTP/2\nPOST /stockroom.v1.StockService/ListWarehouses\nContent-Type: application/grpc+proto\nAuthorization: Bearer <caller token>\n\nprotobuf: ListWarehousesRequest{}\n\nGo handler:\n  StockService.ListWarehouses(ctx, request)\n  → internal/wms.Client.ListWarehouses()`,
      note: "This is not a REST route and it is not an MCP tools/call. The method name and request/response types come from StockService in stock.proto. Code mode uses the same RPC family for CodegenService/RunJavaScript; remote plimsoll uses its own SandboxService/Run, one procedure whose payload names the kind.",
      links: [
        {href: "https://connectrpc.com/", label: "Connect RPC overview", external: true},
        {href: "https://grpc.io/docs/what-is-grpc/core-concepts/", label: "gRPC core concepts", external: true},
        {href: "https://protobuf.dev/overview/", label: "Protocol Buffers overview", external: true}
      ]
    },
    "private-rest": {
      label: "PRIVATE REST",
      title: "/v1/warehouses is ordinary HTTP inside the Node gateway",
      from: "plimsoll broker → Stockroom gateway /v1/warehouses",
      intro: "This is the private API surface used by the Stockroom SDK inside code mode. It is not an MCP tool and it is not a second process. It is a <a class=\"inline-reference external-reference\" href=\"https://hono.dev/docs\" target=\"_blank\" rel=\"noopener\">Hono</a> route in the same Node gateway process that serves /mcp.",
      code: `GET /v1/warehouses HTTP/1.1\nHost: stockroom-gateway\nAuthorization: Bearer <short-lived run token>\n\nNode route handler:\n  app.get(\"/v1/warehouses\", ...\n    stockClient.listWarehouses({})\n  )\n\nThen the gateway becomes a Connect client\nfor Go StockService/ListWarehouses.`,
      note: "The broker chooses the origin and adds the server-held credential. The Node route turns the REST request into a typed StockService RPC. It does not call the WMS or ERP itself.",
      links: [
        {href: "brokering.html", label: "API broker trainer"},
        {href: "capabilities.html", label: "Capability grant trainer"},
        {href: "https://www.jsonrpc.org/specification", label: "JSON-RPC 2.0 specification", external: true}
      ]
    },
    "plimsoll-rpc": {
      label: "PLIMSOLL RPC",
      title: "Code execution is local or a versioned remote RPC",
      from: "Stockroom Go dataplane → plimsoll",
      intro: "The Go CodegenService is the Stockroom admission point. With a local provider, it calls the sandbox package in-process. With PLIMSOLL_URL configured, it uses the standalone plimsolld Connect/gRPC service.",
      code: `LOCAL\nGo CodegenService\n  → sandbox.Request{Code, Grant}\n  → Docker or WASM provider\n\nREMOTE\nGo CodegenService\n  → SandboxService/Run\n    protocol: 1\n    javascript: { code, grant_profile: stockroom }\n  → plimsolld\n  → Docker or E2B provider`,
      note: "The remote request selects a server-side grant profile. It does not send a raw BaseURL or bearer from the model. The local option is not a native-process escape: the selected provider still owns the execution boundary.",
      links: [
        {href: "integrations.html", label: "Integration trainer"},
        {href: "brokering.html", label: "API broker trainer"},
        {href: "https://connectrpc.com/", label: "Connect RPC overview", external: true}
      ]
    },
    "guest-broker": {
      label: "GUEST → BROKER",
      title: "The guest has a host-call transport, not API egress",
      from: "isolated guest → plimsoll broker",
      intro: "The guest runtime can ask for a bounded host operation. Docker frames that request over a per-run Unix socket while WASM crosses a direct wazero host function. Neither gives guest code a normal network client.",
      code: `GUEST CODE\n  inventory.warehouses.list()\n    → host.get(\"/v1/warehouses\")\n\nDOCKER\n  guest Node → /run/host-api.sock → broker\n\nWASM\n  QuickJS → bounded wazero host function → broker\n\nThe guest sends method/path/body.\nThe broker supplies origin/token/policy.`,
      note: "This is where the domain SDK and generic host API meet. The token remains in Go, the BaseURL remains in the grant, and the broker checks the approved route against the exact wire target before making the HTTP request.",
      links: [
        {href: "brokering.html", label: "API broker trainer"},
        {href: "capabilities.html", label: "Capability grant trainer"}
      ]
    }
  };

  function processInspector(processId) {
    const fact = processFacts[processId];
    if (!fact) return;
    const category = processId === "private" ? "LAYER" : (processId === "external" ? "EXTERNAL SERVICE" : "PROCESS");
    byId("processInspector").innerHTML = `
      <span class="inspector-label">${category} ${processId.toUpperCase()}</span>
      <strong>${fact.label}</strong>
      <p>${fact.source}</p>
      ${(fact.links || []).length ? `<div class="inspector-links"><b>Learn more:</b> ${(fact.links || []).map((link) => `<a href="${link.href}"${link.external ? ' target="_blank" rel="noopener"' : ""}>${link.external ? "EXTERNAL · official docs ↗" : "INTERNAL · trainer site →"} ${link.label}</a>`).join(" · ")}</div>` : ""}
      <div class="inspector-columns">
        <div><span>RECEIVES</span><b>${fact.input}</b></div>
        <div><span>SENDS</span><b>${fact.output}</b></div>
        <div><span>DOES NOT OWN</span><b>${fact.boundary}</b></div>
      </div>`;
    document.querySelectorAll(".process-card").forEach((card) => card.classList.toggle("selected", card.dataset.process === processId));
  }

  function renderExposure(kind, lane = "code") {
    const copy = lane === "direct" ? directExposureCopy[kind] : exposureCopy[kind];
    byId("exposurePanel").innerHTML = `
      <div class="exposure-copy"><span class="panel-label">${kind.toUpperCase()} WINDOW</span><h3>${copy.title}</h3><p>${copy.intro}</p><p class="exposure-note">${copy.note}</p></div>
      <pre class="exposure-code"><code></code></pre>`;
    byId("exposurePanel").querySelector("code").textContent = copy.code;
    document.querySelectorAll(".exposure-tab").forEach((tab) => {
      const active = tab.dataset.exposure === kind;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
    });
  }

  function renderProtocol(kind) {
    const copy = protocolCopy[kind];
    const links = copy.links.map((link) => `<a href="${link.href}"${link.external ? ' target="_blank" rel="noopener"' : ""}>${link.external ? "EXTERNAL · official docs ↗" : "INTERNAL · trainer site →"} ${link.label}</a>`).join(" · ");
    byId("protocolPanel").innerHTML = `
      <div class="protocol-copy"><span class="panel-label">${copy.label}</span><h3>${copy.title}</h3><p class="protocol-direction"><b>FROM</b> ${copy.from}</p><p>${copy.intro}</p><p class="protocol-note">${copy.note}<br><br><b>Learn more:</b> ${links}</p></div>
      <pre class="protocol-code"><code></code></pre>`;
    byId("protocolPanel").querySelector("code").textContent = copy.code;
    document.querySelectorAll(".protocol-tab").forEach((tab) => {
      const active = tab.dataset.protocol === kind;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
    });
  }

  function renderProcessHighlights(activeProcesses) {
    const active = new Set(activeProcesses || []);
    document.querySelectorAll(".process-card").forEach((card) => card.classList.toggle("traced", active.has(card.dataset.process)));
  }

  function initTheme() {
    const root = document.documentElement;
    const button = byId("themeToggle");
    let theme = "light";
    try {
      const saved = window.localStorage.getItem("plimsoll-flight-theme");
      if (saved === "light" || saved === "dark") theme = saved;
    } catch (_) {
      // File URLs and privacy modes may deny localStorage. The toggle still works for this visit.
    }

    const apply = (nextTheme) => {
      theme = nextTheme;
      root.dataset.theme = theme;
      if (!button) return;
      const light = theme === "light";
      button.setAttribute("aria-pressed", String(light));
      button.setAttribute("aria-label", light ? "Switch to dark theme" : "Switch to light theme");
      button.querySelector(".theme-icon").textContent = light ? "☾" : "☼";
      button.querySelector(".theme-label").textContent = light ? "Dark mode" : "Light mode";
    };

    apply(theme);
    if (button) button.addEventListener("click", () => {
      const nextTheme = theme === "dark" ? "light" : "dark";
      apply(nextTheme);
      try { window.localStorage.setItem("plimsoll-flight-theme", nextTheme); } catch (_) { /* see above */ }
    });
  }

  function init() {
    initTheme();
    const state = { lane: "code", deployment: "local", current: -1, timer: null };
    const timeline = byId("traceTimeline");

    function steps() { return state.lane === "code" ? codeTrace(state.deployment) : directTrace; }

    function renderDetail() {
      const list = steps();
      const step = list[state.current];
      byId("detailCount").textContent = state.current < 0 ? `0 / ${list.length}` : `${state.current + 1} / ${list.length}`;
      if (!step) {
        byId("detailStatus").textContent = "READY";
        byId("detailTitle").textContent = "Choose a trace";
        byId("detailBody").textContent = "The direct MCP path and code mode may end at the same private service, but they do not have the same process graph. Play either trace to see the difference.";
        byId("wireLabel").textContent = "WIRE INSPECTOR";
        byId("wirePayload").textContent = "Select Code mode or Direct MCP, then press Play trace.";
        byId("detailBoundary").innerHTML = "";
        renderProcessHighlights([]);
        return;
      }
      byId("detailStatus").textContent = step.tag.toUpperCase();
      byId("detailTitle").textContent = step.title;
      byId("detailBody").textContent = `${step.actor}: ${step.body}`;
      byId("wireLabel").textContent = "MESSAGE ON THIS HOP";
      byId("wirePayload").textContent = step.wire;
      byId("detailBoundary").innerHTML = `<span>BOUNDARY NOTE</span><p>${step.boundary}</p>`;
      renderProcessHighlights(step.process);
    }

    function renderTimeline() {
      const list = steps();
      timeline.innerHTML = list.map((step, index) => {
        const stateClass = index === state.current ? "active" : (index < state.current ? "done" : "");
        return `<button class="timeline-step ${stateClass}" data-step="${index}"><span class="timeline-number">${String(index + 1).padStart(2, "0")}</span><span><b>${step.title}</b><small>${step.actor}</small></span><i></i></button>`;
      }).join("");
      timeline.querySelectorAll("[data-step]").forEach((button) => button.addEventListener("click", () => {
        stop();
        state.current = Number(button.dataset.step);
        renderTimeline();
        renderDetail();
      }));
    }

    function stop() {
      if (state.timer) window.clearInterval(state.timer);
      state.timer = null;
      byId("playTrace").classList.remove("playing");
      byId("playTrace").innerHTML = "<span>▶</span> Play trace";
    }

    function play() {
      if (state.timer) { stop(); return; }
      if (state.current >= steps().length - 1) state.current = -1;
      byId("playTrace").classList.add("playing");
      byId("playTrace").innerHTML = "<span>Ⅱ</span> Pause trace";
      state.timer = window.setInterval(() => {
        state.current += 1;
        renderTimeline();
        renderDetail();
        if (state.current >= steps().length - 1) stop();
      }, 980);
      state.current = 0;
      renderTimeline();
      renderDetail();
    }

    document.querySelectorAll(".process-card").forEach((card) => card.addEventListener("click", () => {
      processInspector(card.dataset.process);
      if (window.innerWidth <= 1050) byId("processInspector").scrollIntoView({ behavior: "smooth", block: "nearest" });
    }));
    document.querySelectorAll(".trace-mode").forEach((button) => button.addEventListener("click", () => {
      stop(); state.lane = button.dataset.lane; state.current = -1;
      document.querySelectorAll(".trace-mode").forEach((item) => item.classList.toggle("active", item === button));
      document.querySelectorAll(".deployment-choice").forEach((item) => { item.disabled = state.lane === "direct"; item.classList.toggle("muted", state.lane === "direct"); });
      byId("detailStatus").textContent = state.lane === "direct" ? "DIRECT MCP" : "CODE MODE";
      renderTimeline(); renderDetail();
      renderExposure("model", state.lane);
    }));
    document.querySelectorAll(".deployment-choice").forEach((button) => button.addEventListener("click", () => {
      if (state.lane === "direct") return;
      stop(); state.deployment = button.dataset.deployment; state.current = -1;
      document.querySelectorAll(".deployment-choice").forEach((item) => item.classList.toggle("active", item === button));
      renderTimeline(); renderDetail();
    }));
    document.querySelectorAll(".exposure-tab").forEach((button) => button.addEventListener("click", () => renderExposure(button.dataset.exposure, state.lane)));
    document.querySelectorAll(".protocol-tab").forEach((button) => button.addEventListener("click", () => renderProtocol(button.dataset.protocol)));
    byId("playTrace").addEventListener("click", play);
    byId("resetTrace").addEventListener("click", () => { stop(); state.current = -1; renderTimeline(); renderDetail(); });

    processInspector("model");
    renderTimeline();
    renderExposure("model", state.lane);
    renderProtocol("mcp-http");
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

/* ============================================================
   Small experiments that make the process graph answer back. The
   protocol decoder and trace player remain the primary lesson.
   ============================================================ */
(() => {
  "use strict";

  const byId = (id) => document.getElementById(id);

  const runtimes = {
    runc: {
      name: "runc",
      tier: "container",
      note: "namespaces and cgroups over the host kernel",
      toast: "The default runtime. The guest is separated by namespaces and cgroups, but it is the <b>host</b> kernel underneath, so a kernel bug is a shared risk. The response reports <code>container</code>."
    },
    runsc: {
      name: "runsc",
      tier: "kernel",
      note: "gVisor's user-space kernel between guest and host",
      toast: "Same graph, one flag different. gVisor intercepts the guest's syscalls and services them in user space, so the host kernel sees a far smaller surface. The response now reports <code>kernel</code>. Nothing else in this diagram moved. Type <code>runc</code> to go back."
    }
  };

  const providers = {
    docker: {
      name: "docker",
      wall: "no network + socket",
      detail: "The container is started with no network at all. Calls are framed over a Unix socket created for this run alone, and the broker on the far side is the only thing holding the token.",
      toast: "The guest is a container with <code>--network none</code>, so it cannot dial anything. Every permitted call is framed over a per-run Unix socket to the broker, which is where the credential lives."
    },
    wasm: {
      name: "wasm",
      wall: "one host function",
      detail: "There is no socket and no container. QuickJS calls a single quota-bounded host function, and only the method, path, body, and bounded response cross WASM memory.",
      toast: "No container, no socket. QuickJS reaches one quota-bounded host function, so only <code>{method, path, body}</code> and the bounded response cross WASM memory. The credential never leaves Go. Snippets only: there is no project toolchain here."
    },
    e2b: {
      name: "e2b",
      wall: "deny-all + guard",
      detail: "The microVM denies egress outright and reaches the same broker through a configured guard, so route policy and the credential both stay outside the VM.",
      toast: "The microVM denies egress and reaches the same broker through a configured guard URL. With no guard configured, a grant here is refused rather than quietly downgraded. This was the last of the three to land, and it needed a live allow, deny, and expiry proof."
    }
  };

  const state = {runtime: "runc", provider: "docker"};

  let probeTimers = [];
  let toastTimer = null;

  /* The probe restarts on every press, so it clears only its own timers. */
  const afterProbe = (ms, fn) => { probeTimers.push(setTimeout(fn, ms)); };
  const clearProbeTimers = () => { probeTimers.forEach(clearTimeout); probeTimers = []; };
  const restart = (node) => { void node.offsetWidth; };

  function verdictHTML() {
    const tier = runtimes[state.runtime];
    const transport = providers[state.provider];
    const tierLine = state.provider === "docker"
      ? ` Running ${tier.name}, ${tier.note}, reported as <code>${tier.tier}</code>.`
      : "";
    return `<b>The call crossed. The credential did not.</b> The guest asked for a route by name. ` +
      `The broker checked it against the allowlist, attached the minted token host-side, and made the request itself. ` +
      `The token was never written into guest memory, so there is nothing in there to leak, log, or exfiltrate.` +
      `<i>Wall shown here: <code>${transport.name}</code>, ${transport.detail}${tierLine} ` +
      `Type another provider or runtime name to rebuild it.</i>`;
  }

  function refreshVerdict() {
    const verdict = byId("probeVerdict");
    if (verdict && verdict.classList.contains("shown")) verdict.innerHTML = verdictHTML();
  }

  function showToast(label, body) {
    let toast = byId("tierToast");
    if (!toast) {
      toast = document.createElement("div");
      toast.className = "tier-toast";
      toast.id = "tierToast";
      toast.setAttribute("role", "status");
      document.body.appendChild(toast);
    }
    toast.innerHTML = `<b>${label}</b>${body}`;
    restart(toast);
    toast.classList.add("shown");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("shown"), 10000);
  }

  /* ✦ The "isolated execution" arrow. The one claim the trainer rests on,
     played as motion: the call crosses the wall, the credential does not. */
  function runProbe() {
    const stage = byId("probeStage");
    const probe = byId("boundaryProbe");
    const verdict = byId("probeVerdict");
    if (!stage || !probe || !verdict) return;

    clearProbeTimers();
    stage.hidden = false;
    stage.classList.remove("running", "hit");
    verdict.classList.remove("shown");
    probe.classList.remove("running");
    restart(stage);
    stage.classList.add("running");
    probe.classList.add("running");

    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      stage.classList.add("hit");
      stage.classList.remove("running");
      probe.classList.remove("running");
      verdict.innerHTML = verdictHTML();
      verdict.classList.add("shown");
      return;
    }

    afterProbe(920, () => stage.classList.add("hit"));
    afterProbe(2050, () => {
      stage.classList.remove("running", "hit");
      probe.classList.remove("running");
      verdict.innerHTML = verdictHTML();
      verdict.classList.add("shown");
    });
  }

  /* Typed: a container runtime name. Same graph, different tier. */
  function setRuntime(next) {
    if (next === state.runtime) return;
    state.runtime = next;
    const graph = byId("processGraph");
    if (graph) graph.classList.toggle("kernel-tier", state.runtime === "runsc");
    syncChoices();
    refreshVerdict();
    showToast(`SANDBOX_DOCKER_RUNTIME=${runtimes[state.runtime].name}`, runtimes[state.runtime].toast);
  }

  /* Typed: a provider name. Same claim, a different wall enforcing it. */
  function setProvider(next) {
    if (next === state.provider) return;
    state.provider = next;
    const label = document.querySelector(".probe-wall span");
    if (label) label.textContent = providers[state.provider].wall;
    syncChoices();
    refreshVerdict();
    showToast(`SANDBOX_PROVIDER=${providers[state.provider].name}`, providers[state.provider].toast);
  }

  function syncChoices() {
    document.querySelectorAll("[data-runtime-choice]").forEach((button) => {
      const active = button.dataset.runtimeChoice === state.runtime;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    document.querySelectorAll("[data-provider-choice]").forEach((button) => {
      const active = button.dataset.providerChoice === state.provider;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });
  }

  function initContractCheck() {
    const verdict = byId("contractVerdict");
    if (!verdict) return;
    document.querySelectorAll("[data-contract-answer]").forEach((button) => button.addEventListener("click", () => {
      const correct = button.dataset.contractAnswer === "correct";
      document.querySelectorAll("[data-contract-answer]").forEach((option) => {
        option.classList.toggle("selected", option === button);
        option.classList.toggle("correct", option.dataset.contractAnswer === "correct");
        option.classList.toggle("wrong", option === button && !correct);
        option.setAttribute("aria-pressed", String(option === button));
      });
      verdict.hidden = false;
      verdict.className = `contract-verdict ${correct ? "correct" : "wrong"}`;
      verdict.innerHTML = correct
        ? "<b>Correct.</b> <code>run_javascript</code> is the registered MCP operation. The guest later evaluates <code>inventory.warehouses.list()</code>, which reaches a host-provided global. <code>GET /v1/warehouses</code> is a private REST route inside the gateway."
        : "<b>Not quite.</b> You picked a runtime global or a private route. The MCP host calls <code>run_javascript</code>; plimsoll then starts the guest, where <code>inventory.warehouses.list()</code> can ask the broker for <code>GET /v1/warehouses</code>.";
    }));
  }

  const typedEggs = [
    ["runsc", () => setRuntime("runsc")],
    ["runc", () => setRuntime("runc")],
    ["docker", () => setProvider("docker")],
    ["wasm", () => setProvider("wasm")],
    ["e2b", () => setProvider("e2b")]
  ];

  function init() {
    [
      ["boundaryProbe", runProbe]
    ].forEach(([id, handler]) => {
      const host = byId(id);
      if (host) host.addEventListener("click", handler);
    });

    document.querySelectorAll("[data-runtime-choice]").forEach((button) => button.addEventListener("click", () => setRuntime(button.dataset.runtimeChoice)));
    document.querySelectorAll("[data-provider-choice]").forEach((button) => button.addEventListener("click", () => setProvider(button.dataset.providerChoice)));
    syncChoices();
    initContractCheck();

    let typed = "";
    document.addEventListener("keydown", (event) => {
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      if (event.target.closest && event.target.closest("input, textarea, select, [contenteditable='true']")) return;
      if (event.key.length !== 1) return;
      typed = (typed + event.key.toLowerCase()).slice(-8);
      /* runsc is checked before runc: the longer word ends with the shorter one. */
      const hit = typedEggs.find(([word]) => typed.endsWith(word));
      if (hit) hit[1]();
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
