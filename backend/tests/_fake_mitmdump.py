# ==============================================================================
# Test-support ONLY — a fake `mitmdump` for the LIVE-capture tests (scan_capture). It is NOT shipped
# and NEVER imported by app code; scan_capture is pointed at it via the `mitmdump_cmd` seam so the
# capture lifecycle (spawn -> capture-to-file -> clean process-tree teardown) can be exercised with NO
# real mitmproxy installed and NO network.
#
# Behaviour is driven by env:
#   FAKE_MODE=books  (default) -> bind the listen port, write two in-scope + one off-target request
#                                 block to CAPTURE_FLOW_FILE (so the loader's scope drop is exercised).
#   FAKE_MODE=empty           -> bind the port, write NOTHING (the 0-flows honest-empty path).
#   FAKE_MODE=bootfail        -> exit non-zero immediately (the boot-grace failure path).
#   FAKE_HEARTBEAT_FILE=path  -> ALSO spawn a GRANDCHILD that heartbeats `path` forever and writes its
#                                pid to `path + ".pid"`. The grandchild does NOT clean itself up, so it
#                                survives ONLY if the spawner's process-GROUP teardown fails to reap the
#                                tree — that is the orphan/leak assertion.
# Binding the real listen port lets the port-leak test re-bind after teardown to prove no leak.
# ==============================================================================
import os
import sys
import time
import socket
import subprocess


def _arg(name, default=None):
    a = sys.argv
    if name in a:
        i = a.index(name)
        if i + 1 < len(a):
            return a[i + 1]
    return default


_GRANDCHILD = (
    "import os, time, sys\n"
    "p = sys.argv[1]\n"
    "open(p + '.pid', 'w').write(str(os.getpid()))\n"
    "while True:\n"
    "    open(p, 'a').write('x')\n"
    "    time.sleep(0.03)\n"
)


def main():
    mode = os.environ.get("FAKE_MODE", "books")
    if mode == "bootfail":
        sys.stderr.write("fake mitmdump: failed to bind listen port\n")
        sys.stderr.flush()
        sys.exit(3)

    port = int(_arg("--listen-port", "0"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", port))          # hold the port (no SO_REUSEADDR -> a leak is detectable)
    srv.listen(16)

    flow = os.environ.get("CAPTURE_FLOW_FILE", "")
    if flow and mode == "books":
        blocks = [
            "GET /books/v1/alicebook HTTP/1.1", "Host: 127.0.0.1:5000", "",
            "GET /books/v1/bobbook HTTP/1.1", "Host: 127.0.0.1:5000", "",
            "GET /secret/33 HTTP/1.1", "Host: evil.example.com", "",   # off-target -> loader must drop
        ]
        with open(flow, "a", encoding="utf-8") as fh:
            fh.write("\n".join(blocks) + "\n")
            fh.flush()

    hb = os.environ.get("FAKE_HEARTBEAT_FILE", "")
    if hb:
        # Deliberately NOT tracked for cleanup here — only the spawner's process-tree kill should reap it.
        subprocess.Popen([sys.executable, "-c", _GRANDCHILD, hb])

    while True:
        time.sleep(0.05)


if __name__ == "__main__":
    main()
