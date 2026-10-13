#!/usr/bin/env python3
"""Linux-only test adapter for hotpath 0.21's CPU collector protocol.

Use through HOTPATH_SAMPLY_WRAPPER_BIN. Requires perf and samply on PATH, but
records only cpu-clock:u with small mmap buffers; never changes host policy.
"""

import os, signal, subprocess, sys, time
from pathlib import Path

_, mode, pid, directory = sys.argv
assert mode == "--detach"
directory = Path(directory)
artifacts = Path(os.environ.get("HOTPATH_TEST_ARTIFACT_DIR", directory))
artifacts.mkdir(parents=True, exist_ok=True)
perf_path = artifacts / (pid + ".data")
profile_path = directory / "hp.json.gz"
result = ""
try:
    with (artifacts / (pid + ".log")).open("w") as log:
        process = subprocess.Popen(
            [
                "perf",
                "record",
                "-m",
                "8",
                "-e",
                "cpu-clock:u",
                "-F",
                "999",
                "--call-graph",
                "dwarf",
                "-p",
                pid,
                "-o",
                str(perf_path),
            ],
            stdout=log,
            stderr=log,
        )
        deadline = time.monotonic() + 60
        while not (directory / "stop-profiling").exists():
            if process.poll() is not None:
                raise RuntimeError("perf exited early: " + str(process.returncode))
            if time.monotonic() > deadline:
                raise RuntimeError("stop signal deadline expired")
            time.sleep(0.05)
        process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
        subprocess.run(
            [
                "samply",
                "import",
                "--save-only",
                "--output",
                str(profile_path),
                str(perf_path),
            ],
            stdout=log,
            stderr=log,
            check=True,
            timeout=10,
        )
        import shutil

        shutil.copy2(profile_path, artifacts / (pid + ".json.gz"))
except Exception as error:
    result = str(error)
finally:
    if "process" in locals() and process.poll() is None:
        process.kill()
        process.wait()
    (directory / "done").write_text(result)
