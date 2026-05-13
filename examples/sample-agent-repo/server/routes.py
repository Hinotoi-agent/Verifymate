from server.tools import run_command

# Toy registration string so Verifymate can ground endpoint references.
ROUTES = {
    "POST /api/tools/run": run_command,
}
