"""Run the real IPv4 TCP core with both partial ACK policies under UBSan."""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source", type=Path, default=HERE.parents[1] / "src",
                    help="lwIP src directory")
parser.add_argument("--baseline-only", action="store_true",
                    help="run only the existing Reno behavior (also works on unmodified lwIP)")
args = parser.parse_args()
SRC = args.source.resolve()
sources = sorted((SRC / "core").glob("*.c"))
sources += sorted((SRC / "core/ipv4").glob("*.c"))
sources += [SRC / "netif/ethernet.c"]
for enabled in ((0,) if args.baseline_only else (0, 1)):
    with tempfile.TemporaryDirectory() as directory:
        executable = Path(directory) / "recovery"
        subprocess.run([
            os.environ.get("CC", "cc"), "-std=c99", "-O0", "-g",
            "-fsanitize=undefined", "-fno-sanitize-recover=all",
            f"-DLWIP_TCP_PARTIAL_ACK_RECOVERY={enabled}",
            "-I", str(HERE), "-I", str(SRC / "include"),
            str(HERE / "recovery.c"), *map(str, sources), "-o", str(executable),
        ], check=True)
        subprocess.run([str(executable)], check=True, timeout=10)
