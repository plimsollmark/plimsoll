"""Agno + plimsoll, with a grant: the toolkit's programs can call one web API.

As crewai_grant.py, through Agno's own tool-call path (FunctionCall, as an agent's run loop
drives it), so nothing calls a model service. Install: pip install 'plimsoll-client[agno]'.
Checked: clients/python/examples_docker_test.go runs this file against a real docker daemon
and a stand-in for the API.
"""

from agno.tools.function import FunctionCall

from plimsoll_client.agno import PlimsollTools

from _granted import JS, PY, executor


def main() -> None:
    tools = PlimsollTools(executor())
    function = tools.functions["plimsoll_run_code"]
    function.process_entrypoint()
    print("the model is told of:", function.to_dict()["description"].split("The API:\n", 1)[1].splitlines()[0])
    for code, language in ((JS, "javascript"), (PY, "python")):
        call = FunctionCall(function=function, arguments={"code": code, "language": language})
        call.execute()
        print(language, "->", call.result)


if __name__ == "__main__":
    main()
