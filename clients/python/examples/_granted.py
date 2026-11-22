"""What the granted examples (*_grant.py) share: the daemon they reach, the grant profile and
the API's description the application chose, and the two programs a model might write.

The profile is the operator's, in the daemon's PLIMSOLL_GRANTS_FILE: here "lights", a lights
API whose routes are GET /v1/lights/* and POST /v1/lights/*/on, the second capped at one
call a run. The description is the file plimsoll-specgen wrote for that profile
(plimsoll-specgen -only allow.json -emit description spec.json > description.txt). Neither
is ever the model's: the application reads them and builds the executor with them.
"""

import os

from plimsoll_client import Client
from plimsoll_client.execution import CodeExecutor

# JavaScript: the host client is a global the provider preloads. The second POST is past the
# route's cap (429), and a route the profile does not list is refused before it leaves.
JS = """const light = await host.get("/v1/lights/kitchen");
console.log("GET", JSON.stringify(light));
console.log("POST", JSON.stringify(await host.post("/v1/lights/kitchen/on", {level: 40})));
await host.post("/v1/lights/kitchen/on", {level: 50}).then(() => console.log("second POST answered"), (e) => console.log("second POST", e.status));
await host.get("/v1/doors/front").then(() => console.log("doors answered"), (e) => console.log("doors refused"));
"""

# Python: plimsoll_host, the module the executor writes into a granted Python run.
PY = """import plimsoll_host
print("GET", plimsoll_host.get("/v1/lights/hall"))
try:
    plimsoll_host.get("/v1/doors/front")
except plimsoll_host.HostAPIError as e:
    print("doors refused", e.status)
"""


def executor() -> CodeExecutor:
    client = Client(os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746"), token=os.environ.get("PLIMSOLL_TOKEN"))
    with open(os.environ["PLIMSOLL_GRANT_DESCRIPTION_FILE"], encoding="utf-8") as f:
        description = f.read()
    return CodeExecutor(client, minimum_isolation=os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel"),
                        grant_profile=os.environ.get("PLIMSOLL_GRANT_PROFILE", "lights"), api_description=description)
