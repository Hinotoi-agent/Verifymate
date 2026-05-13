# Critical RCE in agent command tool

Severity: Critical

The repo has `server/tools.py` with `run_command()` which calls subprocess. This is RCE.

Affected files: `server/tools.py`

Impact: arbitrary command execution.
