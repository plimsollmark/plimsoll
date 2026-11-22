# Agent kits: the same four things in every one

An <dfn>*agent kit*</dfn> (also called an agent framework, or an agent SDK: a software
development kit) is a library for building an AI agent, a program in which a language model
picks each next step: the kit calls the model, makes the <dfn>*tool*</dfn> calls the model asks
for (a tool is a named action the model can call) and hands the answers back. LangChain,
CrewAI, Google's ADK (Agent Development Kit) and OpenAI's Agents SDK are kits. If the model is
a cook deciding what to make, the kit is the kitchen, and when the cook writes a program and
wants it run, the kitchen has to hand it to something that cannot burn the house down:
plimsoll.

Part of the [plimsoll README](../README.md).

<!-- the agent kits story: generated from the integration pages' data; edit that, not this text -->
Whatever kit your agent is built with, the moment it runs code it wrote, plimsoll does the same four things. It runs the code behind an [isolation tier](trainers/glossary.html#isolation-tier) it states, refuses when the tier you asked for is not there, says plainly when nothing ran (the one case where a retry is safe), and hands back a record of the run that you can sign for someone else to check later. The kits differ only in how they plug in, as a code tool the model calls, as a sandbox backend that holds the agent's files and shell, or through [MCP](trainers/glossary.html#mcp), and the answer underneath is the same.
<!-- end of the agent kits story -->

## The four things, and where each is proved

1. **It runs the code behind an isolation tier it states.** The tier is one of four, weakest
   first: `process`, `container`, `kernel` (for example Docker under <dfn>*gVisor*</dfn>, a
   separate kernel in user space between the code and your machine's kernel) and `vm`, a
   virtual machine of its own. The daemon states the tier on every answer and in the record it
   keeps of every run. It rests on the daemon's configuration and a check it runs at startup,
   not on proof from the hardware.
   [INTERNAL · isolation tiers and their evidence →](isolation-tiers.md)
2. **It refuses when the tier you asked for is not there.** Every adapter on this page carries
   a <dfn>*floor*</dfn>, the weakest tier it accepts, `kernel` unless you set it lower. A run
   below the floor is refused before any code is handed over, by the adapter or by the daemon.
   A daemon on plain Docker is the `container` tier, so the default refuses it.
   [INTERNAL · asserting a floor →](isolation-tiers.md#asserting-a-floor)
3. **It says plainly whether anything ran.** A refusal made before the code was handed over
   to run carries a mark with its reason, so retrying it, on this daemon or a stronger one,
   cannot run the code twice. An error without the mark means the code may have run, and no
   adapter retries it. What the agent sees: the Python code tools answer `ran: true`,
   `ran: false` with the reason, or `ran: "unknown"`; the TypeScript ones put "Nothing ran" or
   "The code may have run" at the front of the error; the MCP server answers `ran: "no"` or
   `ran: "maybe"`. The Deep Agents and OpenAI backends raise the client's error, whose
   `not_dispatched` field holds the mark, and the Claude Managed Agents worker hands the
   error's message to the model as a tool error.
   [INTERNAL · did anything run? →](run-results.md#did-anything-run-the-error-says-so)
4. **It hands back a record of the run.** A <dfn>*run record*</dfn> is the daemon's statement
   of what was sent, what came back and what it ran under, as SHA-256
   <dfn>*digests*</dfn>, short codes computed from the bytes that change if any byte does. The
   client recomputes them before the agent sees the answer, and a mismatch is an error. The
   daemon holds no key: a program outside it signs records, so that someone else can check
   later what ran. Where the record surfaces: the code tools hand the model its digest
   (`record_sha256`, `recordSha256`); the TypeScript tools also give your code each full record
   (`onRecord`), and ADK keeps it on `result.execution`; the sandbox backends check every
   call's record and chain the records through the [session](trainers/glossary.html#session);
   the MCP server returns records through `get_record` and signs
   [receipts](trainers/glossary.html#receipt) when it is given a key to sign with.
   [INTERNAL · run records and signing →](run-records.md)

## The three ways it plugs in

Which way a kit uses follows from what it asks for: one run per piece of code, or a whole
workspace kept for the agent. A kit with a page under "See a run" has recorded calls you can
replay in the browser. <dfn>*Trigger.dev*</dfn>, a hosted job runner for TypeScript, is listed
with the code tools: its add-on gives a chat task running there the same code tool as the AI
SDK's.

<!-- the three ways in: generated from the integration pages' data; edit that, not this text -->
### A code tool: the model asks to run a piece of code

The model calls one tool, `plimsoll_run_code` in the Python kits and `executeCode` in the TypeScript ones, with its code and any input files, and each call is one run. In Google's ADK and in smolagents the same job is a code executor, which runs each Python block the model writes. The answer tells the model whether the code ran, what it printed, the tier it ran behind and the run record's digest; ADK and smolagents give the model their own result format and keep plimsoll's checked result for your code.

| Kit | Package or extra | Guide | See a run |
|---|---|---|---|
| Vercel AI SDK | `@plimsollmark/client/ai-sdk` | [Vercel AI SDK guide (INTERNAL · documentation →)](ai-sdk.md) | [Vercel AI SDK page (INTERNAL · plimsoll site →)](https://plimsollmark.github.io/plimsoll/integrations/vercel-ai-sdk/index.html) |
| Mastra | `@plimsollmark/client/mastra` | [TypeScript client guide, Mastra (INTERNAL · documentation →)](../clients/typescript/README.md#mastra) | [Mastra page (INTERNAL · plimsoll site →)](https://plimsollmark.github.io/plimsoll/integrations/mastra/index.html) |
| [Trigger.dev](trainers/glossary.html#trigger-dev) | `@plimsollmark/client/trigger` | [Trigger.dev guide (INTERNAL · documentation →)](trigger-dev.md) | [Trigger.dev page (INTERNAL · plimsoll site →)](https://plimsollmark.github.io/plimsoll/integrations/trigger-dev/index.html) |
| Google ADK | `plimsoll-client[adk]` | [Google ADK guide (INTERNAL · documentation →)](google-adk.md) | [Google ADK page (INTERNAL · plimsoll site →)](https://plimsollmark.github.io/plimsoll/integrations/google-adk/index.html) |
| Agno | `plimsoll-client[agno]` | [Python client guide, Agno and CrewAI tools (INTERNAL · documentation →)](../clients/python/README.md#agno-and-crewai-tools) | [Agno page (INTERNAL · plimsoll site →)](https://plimsollmark.github.io/plimsoll/integrations/agno/index.html) |
| CrewAI | `crewai-plimsoll` | [Python client guide, Agno and CrewAI tools (INTERNAL · documentation →)](../clients/python/README.md#agno-and-crewai-tools) | [CrewAI page (INTERNAL · plimsoll site →)](https://plimsollmark.github.io/plimsoll/integrations/crewai/index.html) |
| LangChain | `plimsoll-client[langchain]` | [Python client guide, LangChain tool and Deep Agents backend (INTERNAL · documentation →)](../clients/python/README.md#langchain-tool-and-deep-agents-backend) | [LangChain page (INTERNAL · plimsoll site →)](https://plimsollmark.github.io/plimsoll/integrations/langchain/index.html) |
| smolagents | `smolagents-plimsoll` | [Python client guide, smolagents executor (INTERNAL · documentation →)](../clients/python/README.md#smolagents-executor) | no page yet |

What each keeps between calls, what it leaves out, and whether its code can call a web API:

- **Vercel AI SDK.** `executeCode` keeps nothing. `forConversation` keeps variables and files for one conversation on a daemon that keeps sessions, and each result says whether they were kept. A new process does not get an old conversation's interpreter back, and a sandbox can expire between calls. With a [grant](trainers/glossary.html#grant), `plimsollGrantedCodeTool` gives the model a tool whose code can call one web API's listed routes: JavaScript wherever grants run, Python too on docker and [OpenShell](trainers/glossary.html#openshell); each such call runs in a sandbox of its own, never in a conversation's, and the tool says so ([capability-grants.md](capability-grants.md#from-an-agent-kits-code-tool)).
- **Mastra.** Variables and files for one Mastra thread on a daemon that keeps sessions; each result says whether they were kept. A call without a resource ID runs in a new sandbox every time. A thread's sandbox closes on `dispose`, after 10 minutes without a call, or to make room under the user's cap of 3 sandboxes, least recently used first. With a grant, `plimsollGrantedExecuteCode` does the same as the AI SDK's granted tool ([capability-grants.md](capability-grants.md#from-an-agent-kits-code-tool)).
- **Trigger.dev.** Variables and files for the calls of one chat run on a daemon that keeps sessions, until the run suspends; each result says whether they were kept. The first call after a suspend starts in a new sandbox. A chat whose code calls a web API builds the AI SDK add-on's `plimsollGrantedCodeTool` inside its run: the run's kept sandbox takes no grant ([capability-grants.md](capability-grants.md#from-an-agent-kits-code-tool)).
- **Google ADK.** Nothing: each code block runs in a new sandbox. For files kept across commands, use the ADK environment. Python only. ADK's stateful mode and its CSV optimization are refused. Takes no grant: its Python blocks have no way to name one.
- **Agno.** Nothing: each call runs in a new sandbox. Python and JavaScript, with only the libraries built into the daemon's image: the sandbox has no network and installs nothing. With a grant (`CodeExecutor(grant_profile=..., api_description=...)`, chosen by your application, never by the model), the tool's code can call one web API's listed routes through plimsoll's [broker](trainers/glossary.html#broker), which adds the API's key outside the sandbox: JavaScript on every [provider](trainers/glossary.html#provider) that gives a project run a grant, Python too on docker and openshell (through `plimsoll_host`); the tool says which in its description ([capability-grants.md](capability-grants.md#from-an-agent-kits-code-tool)).
- **CrewAI.** Nothing: each call runs in a new sandbox. Python and JavaScript, with only the libraries built into the daemon's image. A crew with CrewAI's tool cache on never gets a cached answer for this tool, unless a cache handler of its own overrides the lookup. With a grant (`CodeExecutor(grant_profile=..., api_description=...)`, chosen by your application, never by the model), the tool's code can call one web API's listed routes through plimsoll's [broker](trainers/glossary.html#broker), which adds the API's key outside the sandbox: JavaScript on every [provider](trainers/glossary.html#provider) that gives a project run a grant, Python too on docker and openshell (through `plimsoll_host`); the tool says which in its description ([capability-grants.md](capability-grants.md#from-an-agent-kits-code-tool)).
- **LangChain.** Nothing: each call runs in a new sandbox. For files and a shell kept across commands, use the Deep Agents backend. Python and JavaScript, with only the libraries built into the daemon's image. LangGraph's `ToolNode`, `create_agent` and graphs of your own call it like any LangChain tool. With a grant (`CodeExecutor(grant_profile=..., api_description=...)`, chosen by your application, never by the model), the tool's code can call one web API's listed routes through plimsoll's [broker](trainers/glossary.html#broker), which adds the API's key outside the sandbox: JavaScript on every [provider](trainers/glossary.html#provider) that gives a project run a grant, Python too on docker and openshell (through `plimsoll_host`); the tool says which in its description ([capability-grants.md](capability-grants.md#from-an-agent-kits-code-tool)).
- **smolagents.** Variables, functions, imports and files, for one session the executor keeps for the agent: each step of the agent is one [cell](trainers/glossary.html#cell) in the session's Python interpreter. Python only, with only the libraries built into the daemon's image: a tool whose code imports a package from outside Python's standard library is refused when the run starts, and no tool reaches the network. No pickle, and a final answer that is an image or a NumPy value is refused. A refusal, or a step that may have run without an answer, stops the run with the client's error, and each cell's tier, outcome and [run record](trainers/glossary.html#run-record) reach your app in `executor.records`. Takes no grant: each step is a [cell](trainers/glossary.html#cell), and the daemon gives a cell none.

### A sandbox backend: the kit asks for a whole workspace

The kit asks for a shell and files to run the agent's commands in, and plimsoll serves them from one [session](trainers/glossary.html#session), one sandbox kept for many calls. Every command and every file read or write is one call of that session, with its own run record, at the floor the session was opened with. On a refusal the adapter raises the client's error, whose mark says whether anything ran; the Managed Agents worker and ADK's own environment tools turn it into a tool error for the model.

| Kit | Package or extra | Guide | See a run |
|---|---|---|---|
| OpenAI Agents SDK | `plimsoll-client[openai-agents]` | [Python client guide, OpenAI Agents SDK (INTERNAL · documentation →)](../clients/python/README.md#openai-agents-sdk-sandbox-provider) | no page yet |
| Deep Agents (LangChain) | `plimsoll-client[deepagents]` | [Python client guide, LangChain tool and Deep Agents backend (INTERNAL · documentation →)](../clients/python/README.md#langchain-tool-and-deep-agents-backend) | no page yet |
| Google ADK environment | `plimsoll-client[adk]` | [Google ADK guide, the environment (INTERNAL · documentation →)](google-adk.md#a-kept-sandbox-with-a-shell-and-files) | no page yet |
| Microsoft Agent Framework | `agent-framework-plimsoll` | [Python client guide, Microsoft Agent Framework shell tool and code tool (INTERNAL · documentation →)](../clients/python/README.md#microsoft-agent-framework-shell-tool-and-code-tool) | no page yet |
| PydanticAI | `pydantic-ai-plimsoll` (next release) | [Python client guide, PydanticAI workspace (INTERNAL · documentation →)](../clients/python/README.md#pydanticai-workspace) | no page yet |
| Claude Managed Agents | `plimsoll-client[anthropic]` | [Python client guide, Claude Managed Agents worker (INTERNAL · documentation →)](../clients/python/README.md#claude-managed-agents-self-hosted-worker) | no page yet |

What each keeps between calls, what it leaves out, and whether its code can call a web API:

- **OpenAI Agents SDK.** Files, the shell's directory and its exported variables, for the session. On resume the SDK restores its snapshot of the files into a new session. No terminal (PTY), so nothing shows while a command runs, and no exposed ports; everything runs as one user, so the SDK's users and groups are refused; a process left running ends with its command; a workspace past 8 MiB cannot be saved at stop. A refusal ends the agent's run with the SDK's error, and each command's tier and [run record](trainers/glossary.html#run-record) reach your app in the SDK's own sandbox events and trace spans. A workspace call takes no grant.
- **Deep Agents (LangChain).** Files, the shell's directory and its exported variables, for the session, and a thread resumed on another worker keeps them: the backend opened with a [checkpoint store](trainers/glossary.html#checkpoint-store) is taken over by `PlimsollSandbox.attach` ([sessions.md](sessions.md#carrying-a-session-on-from-another-worker)). Needs python3 in the sandbox. A refusal stops the agent's run with the client's error, and once the session ends every later call raises rather than opening a new sandbox. A workspace call takes no grant.
- **Google ADK environment.** Files, for the session. Each command starts a new shell in the work directory, as in ADK's own environments, so a `cd` or an exported variable does not reach the next command. Tested with, and its extra installs, exactly ADK 2.14.1. Commands ADK runs in parallel run one after another, and a process left running ends with its command. With `PlimsollEnvironmentGuard` registered on the Runner, the agent stops after a call that may have run without an answer, and one sandbox serves one ADK user. A workspace call takes no grant.
- **Microsoft Agent Framework.** Files, the shell's directory and its exported variables, for one session the shell tool keeps for the conversation. The package's code tool keeps nothing. The shell is BusyBox sh on plimsoll's docker images. A refusal raises the client's error and the model sees the framework's error result; a command that may have run without an answer stops the agent's run; once the session ends every later command raises rather than opening a new sandbox. The framework's shell support is a beta, and the package requires one exact version of it. The shell's session takes no grant; the package's code tool takes one as the CrewAI tool does ([capability-grants.md](capability-grants.md#from-an-agent-kits-code-tool)).
- **PydanticAI.** Files, for one session the run's workspace keeps across the conversation's runs in the process that opened it; the package's shell tool keeps the shell's directory and exported variables too. The package's code tool keeps nothing. Files only: the workspace does not claim commands, so PydanticAI's Coder and Shell do not work on it, and commands go through the package's own shell tool, where a process left in the background ends with its command. Another process reaches the session only through a [checkpoint store](trainers/glossary.html#checkpoint-store) the capability is given, which takes the session over ([sessions.md](sessions.md#carrying-a-session-on-from-another-worker)); without one it cannot. Durable execution is still refused: no engine's own test runs against the package yet. A call that may have run raises an error no durable engine retries, and an ended session is never replaced. The package requires one exact version of pydantic-ai-slim. The workspace takes no grant; `plimsoll_code_tool` takes one as the CrewAI tool does ([capability-grants.md](capability-grants.md#from-an-agent-kits-code-tool)).
- **Claude Managed Agents.** Files, and the shell's directory and exported variables (kept in files), for one Managed Agents session. The skills the worker downloaded are copied in when the session opens. No memory stores; `read` returns text only; a background job ends with its call. A refusal reaches the model as a tool error. A workspace call takes no grant.

### MCP: for anything else

The agent's host starts plimsoll's MCP server, a Go program, and the model calls its tools: `run_code`, and `open_sandbox` and `close_sandbox` for a sandbox that keeps state. Each result carries the tier and the run record's digest, `get_record` returns the record, and a failure says `ran: "no"` or `ran: "maybe"`.

| Kit | Package or extra | Guide | See a run |
|---|---|---|---|
| Claude Code, Codex, Claude Desktop and other MCP clients | `clients/mcp` | [MCP server setup, with the Reflection Mirror recipe (INTERNAL · documentation →)](../clients/mcp/README.md#setup) | no page yet |

What each keeps between calls, what it leaves out, and whether its code can call a web API:

- **Claude Code, Codex, Claude Desktop and other MCP clients.** Without a sandbox handle, nothing. With a handle from `open_sandbox`, files and interpreter state, until `close_sandbox` or the daemon ends that sandbox. At most `PLIMSOLL_MAX_SANDBOXES` sandboxes open at once, and none is closed to make room. Signed [receipts](trainers/glossary.html#receipt) when it is given a key to sign with, refused on Windows for now. Installed with `PLIMSOLL_GRANT_PROFILE` and `PLIMSOLL_GRANT_DESCRIPTION_FILE`, `run_code` without a sandbox handle can call one web API's listed routes (JavaScript wherever grants run, Python too on docker and openshell); a call with a handle cannot, and `run_code`'s description says both ([capability-grants.md](capability-grants.md#from-an-agent-kits-code-tool)).
<!-- end of the three ways in -->

For LangChain and LangGraph, `retry_on` is the retry rule to give a `RetryPolicy` or `ToolRetryMiddleware`: it retries only an error plimsoll raised before any code ran, for a reason another try may pass (`capacity`, `environment`), and nothing that may have run. When a call of the code tool is traced in LangSmith, the tool adds the run record's digest, the tier, whether the code was sent to the sandbox and the outcome to the tool call's run ([Python client guide, LangChain tool and Deep Agents backend (INTERNAL · documentation →)](../clients/python/README.md#langchain-tool-and-deep-agents-backend); [the retry rule's example](../clients/python/examples/langchain_retry_guard.py)).


## Try one without a model bill

[clients/python/examples/](../clients/python/examples/) holds a short program for eight of the
Python kits: [CrewAI](../clients/python/examples/crewai_tool.py),
[Agno](../clients/python/examples/agno_tool.py),
[LangChain](../clients/python/examples/langchain_tool.py),
[Google ADK](../clients/python/examples/adk_executor.py) (and, for ADK's kept sandbox,
[its environment](../clients/python/examples/adk_environment.py)), the
[OpenAI Agents SDK](../clients/python/examples/openai_agents_sandbox.py),
[Microsoft Agent Framework](../clients/python/examples/agent_framework_shell.py),
[smolagents](../clients/python/examples/smolagents_executor.py) and
[PydanticAI](../clients/python/examples/pydantic_ai_workspace.py) (the last three packages are
new in 0.28.0). Each hands the kit plimsoll's tool or sandbox and has the agent run one
piece of code, or for Agent Framework two shell commands, the second reading the file the first
wrote, for smolagents two steps, the second using a variable the first set, and for PydanticAI a
script its file tool wrote, run by plimsoll's shell tool in the same session. The model in each
is a scripted stand-in (LangChain's own fake chat model, and for the others a few lines written
to the kit's model interface) that asks for its runs and then answers, so no model service is
called; replacing it with a real model is one line. Each file's header says what to install,
which daemon to start and how to run it, and a test runs every one of them against a real Docker
daemon. One more PydanticAI program, [kill the worker, keep the sandbox](../clients/python/examples/pydantic_ai_crash.py),
kills the process running an agent while its command runs and has a second process carry the run on
in the same sandbox: plimsoll's record of the lost call says it ended without an answer, the repeat
that PydanticAI's resume sends is not sent, the model is told so, and the two processes' run
records form one chain the daemon's count at close matches. The refusal covers only a repeat sent
as the first call after the takeover; its header says so first, with every other limit.
