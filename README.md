# SandBlaster: Reversing the Apple Sandbox

SandBlaster is a tool for reversing (decompiling) binary Apple sandbox profiles. Apple sandbox profiles are written in SBPL (*Sandbox Profile Language*), a Scheme-like language, and are then compiled into an undocumented binary format and shipped. Primarily used on iOS, sandbox profiles are present on macOS as well. SandBlaster is, to our knowledge, the first tool that reverses binary sandbox profiles to their original SBPL format. SandBlaster works on iOS from version 7 onwards including iOS 11.

The technical report [SandBlaster: Reversing the Apple Sandbox](https://arxiv.org/abs/1608.04303) presents extensive (though a bit outdated) information on SandBlaster internals.

SandBlaster relied on previous work by [Dionysus Blazakis](https://github.com/dionthegod/XNUSandbox) and Stefan Esser's [code](https://github.com/sektioneins/sandbox_toolkit) and [slides](https://www.slideshare.net/i0n1c/ruxcon-2014-stefan-esser-ios8-containers-sandboxes-and-entitlements).

The reverser (in the `reverse-sandbox/` folder) and the helper tool (in the `helpers/` folder) run on any Python running platform.

SandBlaster may be installed and run standalone, though we recommend installing and running it from within [iExtractor](https://github.com/malus-security/iExtractor). Check the [iExtractor documentation](https://github.com/malus-security/iExtractor/blob/master/README.md) for information.

iExtractor is open source software released under the 3-clause BSD license.

## Installation

SandBlaster runs on Python 3. The reverser (in `reverse-sandbox/`) has no
third-party dependencies. The two extraction front-ends in `helpers/` have
different needs:

  * `helpers/ipsw_extract.py` (recommended, modern firmware) drives
    [`ipsw`](https://github.com/blacktop/ipsw) and needs it on `$PATH`:
    ```
    # macOS
    brew install blacktop/tap/ipsw
    # Linux: see https://github.com/blacktop/ipsw#install
    ```
  * `helpers/extract_sandbox_data.py` (legacy path, iOS ≤ 12) parses Mach-O
    binaries directly with `lief`:
    ```
    pip3 install lief
    ```
    If the installation of `lief` fails you need to compile it. More
    information about how to compile it can be found on the
    [wiki page](https://lief.quarkslab.com/doc/stable/compilation.html).

## Usage

In order to use SandBlaster you need access to the binary sandbox profiles and
the sandbox operations, a set of strings that define sandbox-specific actions.

### Modern firmware with `ipsw` (iOS 13+, including iOS 27.2)

On current iOS the sandbox collection and the operations list live inside the
`com.apple.security.sandbox` extension of the (fileset) kernelcache.
`helpers/ipsw_extract.py` uses [`ipsw`](https://github.com/blacktop/ipsw) to
download the kernel (or extract it remotely from an IPSW URL without
downloading the whole archive) and to carve out the two inputs the reverser
consumes: a `*.sb_ops` operations file and a `sandbox_bundle` collection blob.

```
cd helpers/

# Download the kernel for a device/version, extract, and reverse in one go.
./ipsw_extract.py --device iPhone16,1 --version 27.2 -o ./out --reverse -r 27.2

# Or extract the kernel remotely from an IPSW URL (no full download).
./ipsw_extract.py --url https://.../iPhone16,1_27.2_Restore.ipsw -o ./out

# Or reuse a kernelcache you already have on disk.
./ipsw_extract.py --kernelcache ./kernelcache.release.iPhone16,1 -o ./out
```

Here `ipsw` is used purely for firmware plumbing — downloading / remotely
extracting the kernelcache and carving the `com.apple.security.sandbox` KEXT
out of it — and SandBlaster's own `extract_sandbox_data.py` then reads the
operations list and profile collection out of that KEXT. Without `--reverse`
the script prints the exact `reverse_sandbox.py` command to run next against
the extracted `out/sandbox_bundle` and `out/sandbox.sb_ops`.

The kernel download, remote extraction and KEXT extraction steps are validated
against real firmware (e.g. iOS 17.0).

> **Known limitation on iOS 15+ (including iOS 27.2):** the *native extractor
> and reverser do not yet understand the modern sandbox collection.* SandBlaster
> was built for the iOS 9–14 bundle format; on iOS 15+ the sandbox KEXT is an
> arm64e Mach-O whose operation table is stored as chained-fixup pointers, and
> the profile collection is Apple's newer *protobox* layout rather than the
> classic `0x8000` bundle. `extract_sandbox_data.py` therefore cannot currently
> recover the operations list or the collection from an iOS 15+ KEXT, so the
> end-to-end native pipeline stops at extraction for those releases. The ipsw
> acquisition front-end above still works; reversing modern collections needs
> the protobox format and chained-fixup handling to be implemented (see the
> "Supported iOS Versions" section).

### Legacy firmware (iOS ≤ 12)

Sandbox operations and sandbox profiles can also be extracted using the
`helpers/extract_sandbox_data.py` script, which parses Mach-O binaries with
`lief`. Sandbox profiles are extracted from the kernel sandbox extension (as a
bundle for iOS 4 and 9-11) or from kernel cache (as a bundle for iOS 12) or
from the `sandboxd` file in the iOS filesystem (for iOS 5-8). Sandbox
operations are extracted either from kernel extension (for iOS 4-11) or from
kernel cache (for iOS 12).

So, as input data, this legacy path requires the kernelcache, the kernel
sandbox extension and the `sandboxd` file. Information and scripts on
extracting them from a publicly available IPSW (*iPhone Software*) file is
presented by [iExtractor](https://github.com/malus-security/iExtractor).

Below are the steps and commands to reverse the sandbox profiles for iOS 8.4.1, assuming the sandbox kernel extension (`com.apple.security.sandbox.kext`) and the `sandboxd` file are available:

```
# Extract sandbox operations from kernelcache.
cd helpers/
./extract_sandbox_data.py -o iPad2,1_8.4.1_12H321.sb_ops iPad2,1_8.4.1_12H321.com.apple.security.sandox.kext 8.4.1
# Extract binary sandbox profile files from sandboxd.
mkdir iPad2,1_8.4.1_12H321.sandbox_profiles
./extract_sandbox_data.py -O iPad2,1_8.4.1_12H321.sandbox_profiles/ iPad2,1_8.4.1_12H321.sandboxd 8.4.1
# Reverse all binary sandbox profiles.
cd ../reverse-sandbox/
mkdir iPad2,1_8.4.1_12H321.reversed_profiles
for i in ../helpers/iPad2,1_8.4.1_12H321.sandbox_profiles/*; do python reverse_sandbox.py -r 8.4.1 -o ../helpers/iPad2,1_8.4.1_12H321.sb_ops -d iPad2,1_8.4.1_12H321.reversed_profiles/ "$i"; done
```

Below are the steps and commands to reverse the sandbox profiles for iOS 9.3, assuming the sandbox kernel extension (`com.apple.security.sandbox.kext`) is available:

```
# Extract sandbox operations from kernelcache.
cd helpers/
./extract_sandbox_data.py -o iPhone5,1_9.3_13E237.sb_ops iPhone5,1_9.3_13E237.com.apple.security.sandox.kext 9.3
# Extract sandbox profile bundle from kernel sandbox extension.
./extract_sandbox_data.py -O . iPhone5,1_9.3_13E237.com.apple.security.sandox.kext 9.3
cd ../reverse-sandbox/
# Reverse all binary sandbox profiles in sandbox bundle.
mkdir iPhone5,1_9.3_13E237.reversed_profiles
# Print all sandbox profiles in bundle.
python reverse_sandbox.py -r 9.3 -o ../helpers/iPhone5,1_9.3_13E237.sb_ops -d iPhone5,1_9.3_13E237.reversed_profiles/ ../helpers/sandbox_bundle -psb
# Do actual reversing.
python reverse_sandbox.py -r 9.3 -o ../helpers/iPhone5,1_9.3_13E237.sb_ops -d iPhone5,1_9.3_13E237.reversed_profiles/ ../helpers/sandbox_bundle
```

The extraction of the binary sandbox profiles differs between iOS <= 8 and iOS >= 9. Since iOS >= 9 the binary sandbox profiles are stored in a sandbox bundle in the kernel sandbox extension. The `helpers/extract_sandbox_data.py` script extracts them appropriately depending on the iOS version.

The `-psb` option for `reverse_sandbox.py` prints out the sandbox profiles part of a sandbox bundle without doing the actual reversing.

The `reverse_sandbox.py` script needs to be run in its directory (`reverse-sandbox/`) since it needs the other Python modules and the `logger.config` file.

## Internals

The `helpers/` subfolder contains helper scripts that provide a nicer interface for the external tools.

The actual reverser is part of the `reverse-sandbox/` folder. Files here can be categorized as follows:

  * The main script is `reverse_sandbox.py`. It parses the command line arguments, does basic parsing of the input binary file (extracts sections) and calls the appropriate functions from the other modules.
  * The core of the implementation is `operation_node.py`. It provides functions to build the rules graph corresponding to the sandbox profile and to convert the graph to SBPL. It is called by `reverse_sandbox.py`.
  * Sandbox filters (i.e. match rules inside sandbox profiles) are handled by the implementation in `sandbox_filter.py` and the configuration in `filters.json`, `filter_list.py` and `filters.py`. Filter specific functions are called by `operation_node.py`.
  * Regular expression reversing is handled by `sandbox_regex.py` and `regex_parse.py`. `regex_parse.py` is the back end parser that converts the binary representation to a basic graph. `sandbox_regex.py` converts the graph representation (an automaton) to an actual regular expression (i.e. a string of characters and metacharacters). It is called by `reverse_sandbox.py` for parsing regular expressions, with the resulting regular expression list being passed to the functions exposed by `operation_node.py`; `operation_node.py` passes them on to sandbox filter handling files.
  * The new format for storing strings since iOS 10 is handled by `reverse_string.py`. The primary `SandboxString` class in `reverse_string.py` is used in `sandbox_filter.py`.
  * Logging is configured in the `logger.config` file. By default, `INFO` and higher level messages are printed to the console, while `DEBUG` and higher level messages are printed to the `reverse.log` file.

## Supported iOS Versions

SandBlaster works for iOS version 4 onwards. Apple has been making updates to
the binary format of the sandbox profiles: since iOS 9 sandbox profiles are
stored in a bundle, since iOS 10 strings are aggregated together in a
specialized binary format, and iOS 13 reworked the collection header. The
format has been validated up to **iOS 14**.

iOS 15 through **iOS 27** are **partially** supported:

  * **Acquisition works.** `helpers/ipsw_extract.py` uses `ipsw` to download or
    remotely extract the kernelcache and carve out the
    `com.apple.security.sandbox` KEXT. This is validated against real firmware.
  * **Native extraction/reversing does not work yet.** Starting around iOS 15,
    the sandbox KEXT is an arm64e Mach-O whose operation-name table is stored
    as chained-fixup pointers (so SandBlaster's plain-pointer table scan finds
    nothing), and the compiled profile collection uses Apple's newer *protobox*
    layout instead of the classic `0x8000` bundle. `extract_sandbox_data.py`
    and `reverse_sandbox.py` were written for the iOS 9–14 format and do not
    recognize either of these yet.

Making iOS 15+ (including iOS 27.2) fully work therefore requires two pieces of
new reverse-engineering work in SandBlaster itself:

  1. **Chained-fixup-aware extraction** — resolve arm64e chained fixups so the
     operation-order pointer table (and other pointer tables) in the sandbox
     KEXT can be read, to recover the ordered operations list.
  2. **Protobox collection support** — parse the modern collection structure
     the KEXT embeds, rather than the legacy bundle format.

Until that lands, treat iOS 15+ support as acquisition-only. The reverser emits
a warning when run against an unvalidated release, and reverses on a
best-effort basis if it is handed a collection in the legacy bundle format.

## Community

Join us on [Discord](https://discord.gg/m3gjuyHYw9) for live discussions.
