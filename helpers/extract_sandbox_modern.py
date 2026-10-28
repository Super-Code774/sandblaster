#!/usr/bin/env python3

"""Modern (iOS 15+) sandbox data extraction from a kernelcache sandbox KEXT.

``extract_sandbox_data.py`` was written for the iOS 4-14 sandbox kernel
extension, where the sandbox operations table is a plain array of 64-bit
pointers into ``__TEXT,__cstring``. That no longer holds on current firmware:
the sandbox KEXT carved out of a modern fileset kernelcache is an arm64e
Mach-O whose pointers are stored as **chained fixups**, so a scan for plain
pointer values finds nothing and the legacy extractor bails out.

This module recovers the ordered sandbox operations list from such a KEXT.
Rather than implementing a full ``LC_DYLD_CHAINED_FIXUPS`` parser, it exploits
the structure of the kernelcache rebase encoding
(``DYLD_CHAINED_PTR_64_KERNEL_CACHE``), where a rebased pointer stores its
target as a vmoffset from the kernelcache base in the low bits::

    target_vaddr = kernelcache_base + (raw & 0x3FFFFFFF)

The kernelcache base is not recorded in a standalone extracted KEXT, so it is
*solved for* instead of hardcoded: every candidate pointer word is combined
with every known ``__cstring`` address, and the base that explains the most
words wins. This keeps the extractor working across devices and releases,
where the base differs.

With the base known, the operations table is the longest run of adjacent
pointer words that all resolve to C strings and that begins with ``default``
(sandbox operation index 0 is always ``default``).

What this module does **not** do: parse the compiled sandbox profile
collection. On iOS 15+ the collection in the KEXT no longer uses the iOS 13/14
``0x8000`` bundle header, so ``reverse_sandbox.py`` cannot consume it yet. See
the README's "Supported iOS Versions" section.

Usage::

    ./extract_sandbox_modern.py -o ios27.sb_ops com.apple.security.sandbox
"""

import argparse
import collections
import struct
import sys

import lief


# Low bits of a DYLD_CHAINED_PTR_64_KERNEL_CACHE rebase hold the target as a
# vmoffset from the kernelcache base.
FIXUP_TARGET_MASK = 0x3FFFFFFF

# Sections that may hold the operations pointer table. The table lives in a
# const data section; __TEXT,__const is included because older layouts and
# some devices place tables there.
POINTER_SECTIONS = (
    ("__DATA_CONST", "__const"),
    ("__DATA", "__data"),
    ("__TEXT", "__const"),
)

CSTRING_SECTION = ("__TEXT", "__cstring")


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def get_section(binary, segment_name, section_name):
    """Return the named section of ``binary``, or None when absent."""
    segment = binary.get_segment(segment_name)
    if segment is None:
        return None
    for section in segment.sections:
        if section.name == section_name:
            return section
    return None


def read_cstrings(binary):
    """Map virtual address -> string for every C string in ``__cstring``.

    Args:
        binary: the parsed sandbox KEXT Mach-O.

    Returns:
        A dict of {vaddr: str}.
    """
    section = get_section(binary, *CSTRING_SECTION)
    if section is None:
        raise RuntimeError("the KEXT has no __TEXT,__cstring section")

    content = bytes(section.content)
    base_vaddr = section.virtual_address
    strings = {}
    start = 0
    for index, byte in enumerate(content):
        if byte != 0:
            continue
        if index > start:
            raw = content[start:index]
            try:
                strings[base_vaddr + start] = raw.decode("ascii")
            except UnicodeDecodeError:
                pass
        start = index + 1
    return strings


def iter_pointer_words(binary):
    """Yield (section, index, raw_word) for each 64-bit word of each candidate
    pointer-bearing section.
    """
    for segment_name, section_name in POINTER_SECTIONS:
        section = get_section(binary, segment_name, section_name)
        if section is None:
            continue
        content = bytes(section.content)
        count = len(content) // 8
        for index in range(count):
            (word,) = struct.unpack_from("<Q", content, index * 8)
            yield section, index, word


def solve_kernelcache_base(binary, strings):
    """Recover the kernelcache base that the KEXT's chained fixups rebase against.

    Each rebased pointer encodes ``target_vaddr - base`` in its low bits, so
    for a word that targets a known string, ``base == string_vaddr - target``.
    Histogramming that candidate over all (word, string) pairs makes the real
    base the overwhelmingly most common value.

    Only page-aligned candidates are considered, which removes the noise from
    words that are not pointers at all.

    Args:
        binary: the parsed sandbox KEXT Mach-O.
        strings: {vaddr: str} map from :func:`read_cstrings`.

    Returns:
        (base, score) where score is how many words the base explains.

    Raises:
        RuntimeError: when no base can be determined.
    """
    string_vaddrs = list(strings)
    histogram = collections.Counter()

    # Restrict to the small const sections; __TEXT,__const can be megabytes of
    # non-pointer data and only adds noise here.
    for segment_name, section_name in POINTER_SECTIONS[:2]:
        section = get_section(binary, segment_name, section_name)
        if section is None:
            continue
        content = bytes(section.content)
        for index in range(len(content) // 8):
            (word,) = struct.unpack_from("<Q", content, index * 8)
            if word == 0:
                continue
            target = word & FIXUP_TARGET_MASK
            for vaddr in string_vaddrs:
                candidate = vaddr - target
                # The kernel base is page aligned and in the kernel half of the
                # address space.
                if candidate > 0 and candidate & 0xFFF == 0:
                    histogram[candidate] += 1

    if not histogram:
        raise RuntimeError("could not solve the kernelcache base: "
                           "no pointer-like words resolve to __cstring")
    base, score = histogram.most_common(1)[0]
    return base, score


def resolve_runs(binary, strings, base):
    """Return runs of adjacent pointer words that all resolve to strings.

    Args:
        binary: the parsed sandbox KEXT Mach-O.
        strings: {vaddr: str} map.
        base: the solved kernelcache base.

    Returns:
        A list of runs, each a list of resolved strings.
    """
    runs = []

    # Group words per section so a run never spans two sections.
    per_section = collections.OrderedDict()
    for section, index, word in iter_pointer_words(binary):
        per_section.setdefault(section.name, []).append((index, word))

    for _name, words in per_section.items():
        current = []
        for _index, word in words:
            resolved = strings.get(base + (word & FIXUP_TARGET_MASK)) \
                if word else None
            if resolved is None:
                if len(current) > 1:
                    runs.append(current)
                current = []
            else:
                current.append(resolved)
        if len(current) > 1:
            runs.append(current)
    return runs


def extract_operations(binary):
    """Recover the ordered sandbox operations list from a modern sandbox KEXT.

    Args:
        binary: the parsed sandbox KEXT Mach-O.

    Returns:
        The list of sandbox operation names, in operation-index order.

    Raises:
        RuntimeError: when the operations table cannot be located.
    """
    strings = read_cstrings(binary)
    base, score = solve_kernelcache_base(binary, strings)
    eprint("solved kernelcache base: %#x (explains %d pointer words)"
           % (base, score))

    runs = resolve_runs(binary, strings, base)
    # Sandbox operation index 0 is always "default".
    candidates = [run for run in runs if run and run[0] == "default"]
    if not candidates:
        raise RuntimeError("no pointer run starting with 'default' was found; "
                           "the operations table layout may have changed")
    operations = max(candidates, key=len)
    return operations


def main():
    parser = argparse.ArgumentParser(
        description="Extract the ordered sandbox operations list from a modern "
                    "(iOS 15+) sandbox KEXT whose pointers use chained fixups.")
    parser.add_argument("binary", metavar="KEXT",
                        help="path to the extracted com.apple.security.sandbox "
                             "KEXT (see helpers/ipsw_extract.py)")
    parser.add_argument("-o", "--output-sbops", dest="sbops_file", metavar="PATH",
                        default="-",
                        help="file to write the operations list to "
                             "('-' for stdout, the default)")
    args = parser.parse_args()

    parsed = lief.MachO.parse(args.binary)
    if parsed is None:
        eprint("error: could not parse %s as a Mach-O binary" % args.binary)
        return 1
    binary = parsed.at(0) if isinstance(parsed, lief.MachO.FatBinary) else parsed

    try:
        operations = extract_operations(binary)
    except RuntimeError as exc:
        eprint("error: %s" % exc)
        return 1

    text = "\n".join(operations) + "\n"
    if args.sbops_file == "-":
        sys.stdout.write(text)
    else:
        with open(args.sbops_file, "w") as handle:
            handle.write(text)
        eprint("wrote %d sandbox operations to %s"
               % (len(operations), args.sbops_file))
    return 0


if __name__ == "__main__":
    sys.exit(main())
