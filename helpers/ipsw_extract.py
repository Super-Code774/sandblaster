#!/usr/bin/env python3

"""ipsw-based acquisition and extraction front-end for SandBlaster.

Historically SandBlaster relied on iExtractor to download a publicly
available IPSW and carve the kernelcache / sandbox kernel extension out of
it before the ``extract_sandbox_data.py`` helper (which uses ``lief``) could
pull out the sandbox operations table and the binary sandbox profile bundle.

On modern iOS the kernelcache is a fileset Mach-O and the sandbox collection
is embedded in the ``com.apple.security.sandbox`` KEXT, which makes the old
hand-rolled Mach-O carving brittle. blacktop's ``ipsw`` tool
(https://github.com/blacktop/ipsw) handles all of the firmware plumbing for
us: it can download the kernel directly, extract it straight out of a remote
IPSW without downloading the whole archive, and dump the raw sandbox blobs
(the operations list and the sandbox collection) from a kernelcache.

This script drives ``ipsw`` to produce exactly the two inputs the SandBlaster
reverser (``reverse-sandbox/reverse_sandbox.py``) consumes:

  * a ``*.sb_ops`` file  -- the newline separated sandbox operations list;
  * a ``sandbox_bundle`` file -- the raw binary sandbox profile collection.

Example (download the kernel for a device/version, then extract)::

    ./ipsw_extract.py --device iPhone16,1 --version 27.2 -o ./out

Example (remote extraction, no full IPSW download)::

    ./ipsw_extract.py --url https://.../iPhone16,1_27.2_Restore.ipsw -o ./out

Example (reuse a kernelcache you already have)::

    ./ipsw_extract.py --kernelcache ./kernelcache.release.iPhone16,1 -o ./out

Pass ``--reverse`` to chain straight into ``reverse_sandbox.py`` once the
inputs are extracted.

``ipsw`` must be installed and on ``$PATH`` (``brew install
blacktop/tap/ipsw`` on macOS, see the project README for Linux). This script
only shells out to it; it has no third-party Python dependencies.
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys


def eprint(*args, **kwargs):
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def require_ipsw():
    """Make sure the ``ipsw`` binary is available, or abort with guidance."""
    path = shutil.which("ipsw")
    if path is None:
        eprint("error: the 'ipsw' tool was not found on $PATH.")
        eprint("       install it from https://github.com/blacktop/ipsw")
        eprint("       (macOS: `brew install blacktop/tap/ipsw`).")
        sys.exit(2)
    return path


def run_ipsw(args, capture=False):
    """Run ``ipsw`` with the given argument list.

    Args:
        args: argument list passed to ``ipsw`` (without the leading program).
        capture: when True the command's stdout is captured and returned as a
            string instead of being streamed to the terminal.

    Returns:
        The captured stdout string when ``capture`` is True, otherwise None.
    """
    cmd = ["ipsw"] + args
    eprint("+ " + " ".join(cmd))
    if capture:
        proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
        if proc.stderr:
            eprint(proc.stderr.rstrip())
        return proc.stdout
    subprocess.run(cmd, check=True)
    return None


def find_kernelcache(directory):
    """Return the kernelcache path extracted somewhere under ``directory``.

    ``ipsw`` writes the kernelcache to a nested, version specific directory
    layout, so we search recursively and prefer a ``release`` kernelcache when
    several are present (development / research kernelcaches are also shipped
    for some devices).

    Args:
        directory: directory to search.

    Returns:
        The path to a kernelcache file, or None if none was found.
    """
    candidates = []
    for root, _dirs, files in os.walk(directory):
        for name in files:
            lowered = name.lower()
            if lowered.startswith("kernelcache") and not lowered.endswith(
                    (".sb_ops", ".bin.json")):
                candidates.append(os.path.join(root, name))

    if not candidates:
        return None

    # Prefer a release kernelcache; fall back to the first match otherwise.
    for path in candidates:
        if "release" in os.path.basename(path).lower():
            return path
    return candidates[0]


def acquire_kernelcache(args):
    """Obtain a kernelcache according to the chosen acquisition mode.

    Exactly one of ``--kernelcache``, ``--url`` or ``--device`` must have been
    supplied (enforced by the caller). ``--kernelcache`` uses a local file as
    is; ``--url`` performs a remote extraction from an IPSW URL without
    downloading the whole archive; ``--device`` downloads the kernel for a
    device/version from Apple.

    Args:
        args: parsed command line arguments.

    Returns:
        The path to the kernelcache to feed the rest of the pipeline.
    """
    if args.kernelcache:
        if not os.path.isfile(args.kernelcache):
            eprint("error: kernelcache not found: %s" % args.kernelcache)
            sys.exit(2)
        return args.kernelcache

    if args.url:
        # Remote extraction: pull just the kernelcache out of the IPSW URL.
        run_ipsw(["extract", "--kernel", "--remote", args.url,
                  "--output", args.output])
    else:
        # Download the kernel for the requested device/version from Apple.
        download = ["download", "ipsw", "--device", args.device,
                    "--kernel", "--output", args.output, "--confirm"]
        if args.version:
            download += ["--version", args.version]
        else:
            download += ["--latest"]
        run_ipsw(download)

    kernelcache = find_kernelcache(args.output)
    if kernelcache is None:
        eprint("error: no kernelcache was produced under %s" % args.output)
        eprint("       inspect the ipsw output above for what went wrong.")
        sys.exit(1)
    eprint("using kernelcache: %s" % kernelcache)
    return kernelcache


def extract_operations(kernelcache, out_path):
    """Extract the sandbox operations list from ``kernelcache``.

    ``ipsw sb opts`` prints the ordered list of sandbox operations compiled
    into the kernel. The ordering matters: the reverser indexes the profile
    operation table by position, so this list must be written out in the exact
    order ``ipsw`` reports it. We prefer the ``--json`` output (a plain array
    of operation names) and fall back to parsing one-operation-per-line text.

    Args:
        kernelcache: path to the kernelcache.
        out_path: file to write the operations list to.

    Returns:
        The number of operations written.
    """
    ops = None
    try:
        raw = run_ipsw(["sb", "opts", "--json", kernelcache], capture=True)
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            ops = [str(o) for o in parsed]
        elif isinstance(parsed, dict):
            # Some ipsw versions wrap the array, e.g. {"operations": [...]}.
            for value in parsed.values():
                if isinstance(value, list):
                    ops = [str(o) for o in value]
                    break
    except (subprocess.CalledProcessError, json.JSONDecodeError, ValueError):
        ops = None

    if ops is None:
        # Fall back to plain-text output, one operation per line.
        raw = run_ipsw(["sb", "opts", kernelcache], capture=True)
        ops = [line.strip() for line in raw.splitlines() if line.strip()]

    if not ops:
        eprint("error: could not extract any sandbox operations.")
        sys.exit(1)

    with open(out_path, "w") as handle:
        handle.write("\n".join(ops) + "\n")
    eprint("wrote %d sandbox operations to %s" % (len(ops), out_path))
    return len(ops)


def extract_collection(kernelcache, out_dir, out_path):
    """Dump the raw sandbox collection blob from ``kernelcache``.

    ``ipsw sb dump`` writes the raw sandbox blobs (the operations table, the
    individual profiles and the collection/protobox) to disk. The reverser
    wants the whole collection, so once ``ipsw`` has written its blobs we look
    for the collection file and copy it to ``out_path`` under the conventional
    ``sandbox_bundle`` name the reverser documentation uses.

    Args:
        kernelcache: path to the kernelcache.
        out_dir: directory ipsw should dump its blobs into.
        out_path: final path for the sandbox collection blob.

    Returns:
        The path to the sandbox collection blob.
    """
    before = set(glob.glob(os.path.join(out_dir, "*")))
    run_ipsw(["sb", "dump", kernelcache, "--output", out_dir])
    after = set(glob.glob(os.path.join(out_dir, "*")))
    produced = after - before

    # Identify the collection blob among whatever ipsw produced. The collection
    # is the aggregate bundle of every profile; prefer a file that advertises
    # itself as the collection, then a generic sandbox blob.
    def score(path):
        name = os.path.basename(path).lower()
        if "collection" in name:
            return 0
        if "protobox" in name:
            return 1
        if "sandbox" in name:
            return 2
        return 3

    blobs = sorted((p for p in produced if os.path.isfile(p)), key=score)
    if not blobs:
        eprint("error: `ipsw sb dump` did not produce any blob files in %s"
               % out_dir)
        sys.exit(1)

    collection = blobs[0]
    if os.path.abspath(collection) != os.path.abspath(out_path):
        shutil.copyfile(collection, out_path)
    eprint("wrote sandbox collection to %s (from %s)"
           % (out_path, os.path.basename(collection)))
    return out_path


def reverse(bundle_path, ops_path, release, out_dir):
    """Invoke the native SandBlaster reverser on the extracted inputs.

    ``reverse_sandbox.py`` must run from its own directory (it imports sibling
    modules and reads ``logger.config`` relative to the cwd), so we resolve the
    reverser directory and run it from there with absolute input paths.

    Args:
        bundle_path: path to the extracted sandbox collection.
        ops_path: path to the extracted operations list.
        release: iOS release string (e.g. ``27.2``).
        out_dir: directory to write reversed profiles into.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    reverser_dir = os.path.join(os.path.dirname(here), "reverse-sandbox")
    reverser = os.path.join(reverser_dir, "reverse_sandbox.py")
    if not os.path.isfile(reverser):
        eprint("error: could not find the reverser at %s" % reverser)
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)
    cmd = [sys.executable, "reverse_sandbox.py",
           "-r", release,
           "-o", os.path.abspath(ops_path),
           "-d", os.path.abspath(out_dir),
           os.path.abspath(bundle_path)]
    eprint("+ (cd %s && %s)" % (reverser_dir, " ".join(cmd)))
    subprocess.run(cmd, check=True, cwd=reverser_dir)
    eprint("reversed profiles written to %s" % out_dir)


def main():
    parser = argparse.ArgumentParser(
        description="Download/extract the iOS kernel with ipsw and carve the "
                    "sandbox operations and profile collection out of it for "
                    "SandBlaster.")

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--device", metavar="ID",
                        help="device identifier to download the kernel for "
                             "(e.g. iPhone16,1); combine with --version")
    source.add_argument("--url", metavar="IPSW_URL",
                        help="IPSW URL to remotely extract the kernel from "
                             "(no full download)")
    source.add_argument("--kernelcache", metavar="PATH",
                        help="use an already-extracted kernelcache")

    parser.add_argument("--version", metavar="VER",
                        help="iOS version to download (with --device); "
                             "defaults to the latest if omitted")
    parser.add_argument("-o", "--output", metavar="DIR", default="./ipsw_out",
                        help="working/output directory (default: ./ipsw_out)")
    parser.add_argument("-p", "--prefix", metavar="NAME", default="sandbox",
                        help="basename for the generated .sb_ops file "
                             "(default: sandbox)")
    parser.add_argument("--reverse", action="store_true",
                        help="after extraction, run reverse_sandbox.py on the "
                             "results")
    parser.add_argument("-r", "--release", metavar="VER",
                        help="iOS release string passed to the reverser with "
                             "--reverse; defaults to --version")

    args = parser.parse_args()

    if args.device and not args.version:
        eprint("note: no --version given, downloading the latest release.")
    if args.reverse and not (args.release or args.version):
        parser.error("--reverse needs an iOS release: pass -r/--release "
                     "(or --version when downloading).")

    require_ipsw()
    os.makedirs(args.output, exist_ok=True)

    kernelcache = acquire_kernelcache(args)

    ops_path = os.path.join(args.output, args.prefix + ".sb_ops")
    bundle_path = os.path.join(args.output, "sandbox_bundle")

    extract_operations(kernelcache, ops_path)
    extract_collection(kernelcache, args.output, bundle_path)

    if args.reverse:
        release = args.release or args.version
        reverse(bundle_path, ops_path,
                release, os.path.join(args.output, "reversed_profiles"))
    else:
        eprint("")
        eprint("next: reverse the extracted collection, e.g.")
        eprint("  cd ../reverse-sandbox")
        eprint("  python3 reverse_sandbox.py -r %s -o %s -d reversed %s"
               % (args.release or args.version or "27.2",
                  os.path.abspath(ops_path), os.path.abspath(bundle_path)))


if __name__ == "__main__":
    main()
