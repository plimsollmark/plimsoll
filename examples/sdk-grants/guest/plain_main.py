# The control run: the same image with no grant. Nothing sets a base URL or a key, and
# the run gets the default seccomp profile, under which a socket is Unix or nothing.
from report import report

report({}, {})
