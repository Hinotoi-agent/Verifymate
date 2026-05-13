import subprocess

# Intended agent tool. Vulnerability depends on who can call it.
def run_command(cmd: str):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)
