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

This script uses ``ipsw`` only for the firmware plumbing -- downloading or
remotely extracting the kernelcache and carving the
``com.apple.security.sandbox`` kernel extension out of it -- and then hands
that extension to SandBlaster's own ``extract_sandbox_data.py`` to produce the
two inputs the reverser (``reverse-sandbox/reverse_sandbox.py``) consumes:

  * a ``*.sb_ops`` file  -- the newline separated sandbox operations list;
  * a ``sandbox_bundle`` file -- the raw binary sandbox profile collection.

Keeping the sandbox carving in SandBlaster's native extractor (rather than in
``ipsw``) is deliberate: ``ipsw`` handles the kernel download/extraction, and
SandBlaster stays responsible for understanding the sandbox binary format.

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


def extract_sandbox_kext(kernelcache, out_dir, kext):
    """Carve the sandbox kernel extension out of ``kernelcache`` with ipsw.

    ``ipsw kernel extract <KERNELCACHE> <KEXT>`` writes the named KEXT as a
    standalone Mach-O into the output directory. The sandbox operations table
    and the binary profile collection both live inside this extension, which is
    exactly what SandBlaster's native extractor expects as input.

    Args:
        kernelcache: path to the kernelcache.
        out_dir: directory ipsw should write the KEXT into.
        kext: KEXT bundle identifier to extract
            (default ``com.apple.security.sandbox``).

    Returns:
        The path to the extracted sandbox KEXT Mach-O.
    """
    before = set(glob.glob(os.path.join(out_dir, "*")))
    run_ipsw(["kernel", "extract", kernelcache, kext,
              "--output", out_dir, "--force"])
    after = set(glob.glob(os.path.join(out_dir, "*")))
    produced = [p for p in (after - before) if os.path.isfile(p)]

    # ipsw names the extracted file after the bundle id (optionally with an
    # arch suffix). Prefer a freshly produced file that mentions "sandbox";
    # fall back to scanning the directory in case the file already existed.
    def looks_like_sandbox(path):
        return "sandbox" in os.path.basename(path).lower()

    candidates = [p for p in produced if looks_like_sandbox(p)] or produced
    if not candidates:
        candidates = [p for p in glob.glob(os.path.join(out_dir, "*"))
                      if os.path.isfile(p) and looks_like_sandbox(p)]
    if not candidates:
        eprint("error: `ipsw kernel extract` did not produce the %s KEXT in %s"
               % (kext, out_dir))
        eprint("       run `ipsw kernel kexts %s` to list available KEXT ids."
               % kernelcache)
        sys.exit(1)

    kext_path = candidates[0]
    eprint("extracted sandbox KEXT: %s" % kext_path)
    return kext_path


def major_version(release):
    """Return the major iOS version of a release string such as ``27.2``."""
    try:
        return int(str(release).split(".")[0])
    except ValueError:
        eprint("error: could not parse an iOS major version from %r" % release)
        sys.exit(2)


def native_extract(kext_path, ops_path, bundle_dir, release):
    """Run SandBlaster's native extraction on the sandbox KEXT.

    Two extractors exist, picked by release:

      * iOS <= 14 -- ``extract_sandbox_data.py`` reads both the operations
        list and the profile collection out of the KEXT.
      * iOS 15+ -- the KEXT's pointers are chained fixups, which the legacy
        extractor cannot follow, so ``extract_sandbox_modern.py`` recovers the
        operations list. The compiled collection on these releases no longer
        uses the iOS 13/14 bundle header, so collection extraction is attempted
        but is expected to fail; the operations list is still produced.

    Args:
        kext_path: path to the extracted sandbox KEXT.
        ops_path: path to write the ``.sb_ops`` operations list to.
        bundle_dir: directory the ``sandbox_bundle`` collection is written to.
        release: iOS release string (e.g. ``27.2``).

    Returns:
        The path to the extracted collection, or None when it could not be
        extracted (modern releases).
    """
    here = os.path.dirname(os.path.abspath(__file__))
    legacy = os.path.join(here, "extract_sandbox_data.py")
    modern = os.path.join(here, "extract_sandbox_modern.py")
    bundle_path = os.path.join(bundle_dir, "sandbox_bundle")

    if major_version(release) >= 15:
        # Operations: chained-fixup aware extractor.
        cmd = [sys.executable, modern, "-o", ops_path, kext_path]
        eprint("+ " + " ".join(cmd))
        subprocess.run(cmd, check=True)

        # Collection: not supported on modern releases. Attempt it anyway in
        # case a release reverts to the legacy layout, but swallow the
        # extractor's traceback -- failure is the expected outcome here and the
        # note below explains it.
        cmd = [sys.executable, legacy, "-O", bundle_dir, kext_path, release]
        eprint("+ " + " ".join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        if result.returncode != 0 or not os.path.isfile(bundle_path):
            eprint("")
            eprint("note: recovered the operations list, but could NOT extract "
                   "the sandbox profile collection.")
            eprint("      On iOS 15+ the compiled collection in the KEXT no "
                   "longer uses the iOS 13/14 0x8000 bundle header, so")
            eprint("      reverse_sandbox.py cannot consume it yet. See the "
                   "README (\"Supported iOS Versions\").")
            return None
        return bundle_path

    cmd = [sys.executable, legacy,
           "-o", ops_path, "-O", bundle_dir, kext_path, release]
    eprint("+ " + " ".join(cmd))
    subprocess.run(cmd, check=True)
    if not os.path.isfile(bundle_path):
        eprint("error: the extractor did not produce %s" % bundle_path)
        sys.exit(1)
    eprint("wrote operations to %s and collection to %s"
           % (ops_path, bundle_path))
    return bundle_path


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
    parser.add_argument("--kext", metavar="ID",
                        default="com.apple.security.sandbox",
                        help="sandbox KEXT bundle id to extract "
                             "(default: com.apple.security.sandbox)")
    parser.add_argument("--reverse", action="store_true",
                        help="after extraction, run reverse_sandbox.py on the "
                             "results")
    parser.add_argument("-r", "--release", metavar="VER",
                        help="iOS release string for the extractor/reverser "
                             "(e.g. 27.2); defaults to --version")

    args = parser.parse_args()

    # The native extractor and reverser both need an iOS release string to
    # select their version-specific logic. It comes from --release or, when
    # downloading, from --version.
    release = args.release or args.version
    if release is None:
        parser.error("an iOS release is required: pass -r/--release "
                     "(or --version when downloading).")

    if args.device and not args.version:
        eprint("note: no --version given, downloading the latest release.")

    require_ipsw()
    os.makedirs(args.output, exist_ok=True)

    kernelcache = acquire_kernelcache(args)

    kext_path = extract_sandbox_kext(kernelcache, args.output, args.kext)

    ops_path = os.path.join(args.output, args.prefix + ".sb_ops")
    bundle_path = native_extract(kext_path, ops_path, args.output, release)

    if bundle_path is None:
        eprint("")
        eprint("operations list: %s" % os.path.abspath(ops_path))
        eprint("stopping before reversing: no collection was extracted.")
        sys.exit(1)

    if args.reverse:
        reverse(bundle_path, ops_path,
                release, os.path.join(args.output, "reversed_profiles"))
    else:
        eprint("")
        eprint("next: reverse the extracted collection, e.g.")
        eprint("  cd ../reverse-sandbox")
        eprint("  python3 reverse_sandbox.py -r %s -o %s -d reversed %s"
               % (release,
                  os.path.abspath(ops_path), os.path.abspath(bundle_path)))


if __name__ == "__main__":
    main()
