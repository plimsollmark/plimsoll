"""CrewAI + plimsoll, with a grant: the code tool's programs can call one web API.

The application chooses a grant profile the operator configured on the daemon, and the
description plimsoll-specgen wrote for it, and builds the executor with them (_granted.py).
The tool then tells the model what its code can call, and every run carries the profile:
the code calls the API's routes through plimsoll's broker, outside the sandbox, which adds
the API's key; the code never sees one. The tool is called here as CrewAI calls a tool
(tool.run), once with a JavaScript program and once with a Python one, so nothing calls a
model service.

Install:  pip install crewai-plimsoll
Daemon:   a plimsolld on docker or openshell (Python granted calls need one of them;
          JavaScript works wherever the provider gives a project run a grant) with
          PLIMSOLL_GRANTS_FILE naming a "lights" profile and PLIMSOLL_CLIENTS_FILE a caller
          the profile allows (docs/capability-grants.md, "From an agent kit's code tool").
Run:      PLIMSOLL_URL=... PLIMSOLL_TOKEN=... PLIMSOLL_GRANT_DESCRIPTION_FILE=description.txt python crewai_grant.py
Checked:  clients/python/examples_docker_test.go runs this file against a real docker daemon
          and a stand-in for the API.
"""

import os

for name, value in (("CREWAI_DISABLE_TELEMETRY", "true"), ("OTEL_SDK_DISABLED", "true"), ("CREWAI_TRACING_ENABLED", "false")):
    os.environ.setdefault(name, value)

from crewai_plimsoll import PlimsollCodeTool  # noqa: E402  (after the telemetry switches)

from _granted import JS, PY, executor  # noqa: E402


def main() -> None:
    tool = PlimsollCodeTool(executor())
    print("the model is told of:", tool.description.split("The API:\n", 1)[1].splitlines()[0])
    for code, language in ((JS, "javascript"), (PY, "python")):
        print(language, "->", tool.run(code=code, language=language))


if __name__ == "__main__":
    main()
