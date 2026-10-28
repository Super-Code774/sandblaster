#!/usr/bin/env python3

"""
iOS/OS X sandbox decompiler

Heavily inspired from Dion Blazakis' previous work
    https://github.com/dionthegod/XNUSandbox/tree/master/sbdis
Excellent information from Stefan Essers' slides and work
    http://www.slideshare.net/i0n1c/ruxcon-2014-stefan-esser-ios8-containers-sandboxes-and-entitlements
    https://github.com/sektioneins/sandbox_toolkit
"""

import sys
import struct
import logging
import logging.config
import argparse
import os
import re
import operation_node
import sandbox_filter
import sandbox_regex


logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)

# Newest major iOS release whose binary sandbox format has been validated
# against real firmware. Releases from 13 onwards share the same collection
# layout, so newer majors (15 .. 27+) are parsed with the iOS 13+ code path.
# This is best-effort for unvalidated releases: see warn_if_unvalidated().
LAST_VALIDATED_MAJOR = 14
LATEST_MAJOR = 27

# --- Modern collection format (iOS 15+, format version byte 0xCC) -----------
#
# Recovered from the sandbox KEXT's own collection_init() on iOS 27.2. The
# header is byte-oriented rather than the u16 layout used up to iOS 14:
#
#   +0x0  u16  magic (0x8000)
#   +0x2  u16  operation node count
#   +0x4  u8   format version (0xCC)
#   +0x5  u8   global variable count
#   +0x6  u8   profile flag count
#   +0x7  u8   base ("common") profile count
#   +0x8  u8   state flag count
#   +0x9  u8   unused
#   +0xa  u16  profile count
#   +0xc  u16  regex count
#   +0xe  u16  auxiliary table count
#
# Six u16 tables follow at 0x10 in this order: regexes, global variables,
# profile flags, base profiles, state flags, auxiliary. The profile array
# follows, then the operation nodes, then the string/regex data area that
# every table offset indexes (as base_addr + offset * 8).
MODERN_FORMAT_VERSION = 0xCC

# The kernel hardcodes the profile entry size, so SandBlaster does too. Each
# entry is four u16 fields (name offset, flags, and two more) followed by the
# per-operation node offset table, hence 416 / 2 - 4 = 204 operations.
MODERN_PROFILE_ENTRY_SIZE = 416
MODERN_PROFILE_OP_TABLE_OFFSET = 8


def is_modern_format(f):
    """Return True when the file is a modern (0xCC) sandbox collection."""
    pos = f.tell()
    f.seek(4)
    version = f.read(1)
    f.seek(pos)
    return len(version) == 1 and version[0] == MODERN_FORMAT_VERSION


def parse_modern_header(f):
    """Parse a modern sandbox collection header into a dict of counts/offsets.

    Args:
        f: open binary collection file.

    Returns:
        A dict describing the collection layout.
    """
    f.seek(0)
    hdr = f.read(0x10)

    counts = {
        "magic": struct.unpack("<H", hdr[0:2])[0],
        "op_nodes_count": struct.unpack("<H", hdr[2:4])[0],
        "version": hdr[4],
        "global_count": hdr[5],
        "profile_flag_count": hdr[6],
        "base_profile_count": hdr[7],
        "state_flag_count": hdr[8],
        "profiles_count": struct.unpack("<H", hdr[10:12])[0],
        "regex_count": struct.unpack("<H", hdr[12:14])[0],
        "aux_count": struct.unpack("<H", hdr[14:16])[0],
    }

    # The six u16 tables, in file order.
    offset = 0x10
    for name, key in (("regex_table", "regex_count"),
                      ("global_table", "global_count"),
                      ("profile_flag_table", "profile_flag_count"),
                      ("base_profile_table", "base_profile_count"),
                      ("state_flag_table", "state_flag_count"),
                      ("aux_table", "aux_count")):
        counts[name] = offset
        offset += counts[key] * 2

    counts["profile_table"] = offset
    end = offset + counts["profiles_count"] * MODERN_PROFILE_ENTRY_SIZE
    # The kernel rounds the end of the profile array up to an 8 byte boundary
    # using the (unaligned) low bits of the profile table offset.
    if offset & 6:
        end = end - (offset & 6) + 8
    counts["op_nodes_offset"] = end
    counts["base_addr"] = end + counts["op_nodes_count"] * 8
    counts["num_sb_ops"] = \
        MODERN_PROFILE_ENTRY_SIZE // 2 - MODERN_PROFILE_OP_TABLE_OFFSET // 2
    return counts


def extract_string_from_offset(f, offset, ios_version):
    """Extract string (literal) from given offset."""
    if ios_version >= 13:
        f.seek(get_base_addr(f, ios_version) + offset * 8)
        len = struct.unpack("<H", f.read(2))[0]-1
    else:
        f.seek(offset * 8)
        len = struct.unpack("<I", f.read(4))[0]-1
    return '%s' % f.read(len)


def create_operation_nodes(infile, regex_list, num_operation_nodes,
        ios_major_version, keep_builtin_filters, global_vars):
    # Read sandbox operations.
    operation_nodes = operation_node.build_operation_nodes(infile,
        num_operation_nodes, ios_major_version)
    logger.info("operation nodes")
    
    for idx, node in enumerate(operation_nodes):
        logger.info("%d: %s", idx, node.str_debug())
    
    for n in operation_nodes:
        n.convert_filter(sandbox_filter.convert_filter_callback, infile,
                    regex_list, ios_major_version, keep_builtin_filters,
                    global_vars, get_base_addr(infile, ios_major_version))
    logger.info("operation nodes after filter conversion")
    for idx, node in enumerate(operation_nodes):
        logger.info("%d: %s", idx, node.str_debug())

    return operation_nodes


def process_profile(infile, outfname, sb_ops, ops_to_reverse, op_table, operation_nodes):
    outfile = open(outfname, "wt")
    outfile_xml = open(outfname + ".xml", "wt")

    # Print version.
    outfile.write("(version 1)\n")

    outfile_xml.write('<?xml version="1.0" encoding="us-ascii" standalone="yes"?>\n')
    outfile_xml.write('<!DOCTYPE operations [\n')
    outfile_xml.write('<!ELEMENT operations (operation*)>\n')
    outfile_xml.write('<!ELEMENT operation (filters?)>\n')
    outfile_xml.write('<!ELEMENT filters (filter | require)*>\n')
    outfile_xml.write('<!ELEMENT require (filter | require)*>\n')
    outfile_xml.write('<!ELEMENT filter (#PCDATA)>\n')
    outfile_xml.write('<!ATTLIST operation\n')
    outfile_xml.write('\tname CDATA #REQUIRED\n')
    outfile_xml.write('\taction (deny|allow) #REQUIRED>\n')
    outfile_xml.write('<!ATTLIST require\n')
    outfile_xml.write('\ttype (require-all|require-any|require-not|require-entitlement) #REQUIRED\n')
    outfile_xml.write('\tvalue CDATA #IMPLIED>\n')
    outfile_xml.write('<!ATTLIST filter\n')
    outfile_xml.write('\tname CDATA #REQUIRED\n')
    outfile_xml.write('\targument CDATA #IMPLIED>\n')
    outfile_xml.write(']>\n')
    outfile_xml.write("<operations>\n")

    # Extract node for 'default' operation (index 0).
    default_node = operation_node.find_operation_node_by_offset(operation_nodes, op_table[0])
    outfile.write("(%s default)\n" % (default_node.terminal))
    outfile_xml.write("\t<operation name=\"default\" action=\"%s\" />\n" % (default_node.terminal))

    # For each operation expand operation node.
    for idx in range(1, len(op_table)):
        offset = op_table[idx]
        operation = sb_ops[idx]
        # Go past operations not in list, in case list is not empty.
        if ops_to_reverse:
            if operation not in ops_to_reverse:
                continue
        logger.info("parsing operation %s (index %d)", operation, idx)
        node = operation_node.find_operation_node_by_offset(operation_nodes, offset)
        if not node:
            logger.info("operation %s (index %d) has no operation node", operation, idx)
            continue
        g = operation_node.build_operation_node_graph(node, default_node)
        if g:
            rg = operation_node.reduce_operation_node_graph(g)
            rg.str_simple_with_metanodes()
            rg.print_vertices_with_operation_metanodes(operation, default_node.terminal.is_allow(), outfile)
            #rg.dump_xml(operation, outfile_xml)
        else:
            logger.info("no graph for operation %s (index %d)", operation, idx)
            if node.terminal and default_node.terminal:
                if node.terminal.type != default_node.terminal.type:
                    outfile.write("(%s %s)\n" % (node.terminal, operation))
                    outfile_xml.write("\t<operation name=\"%s\" action=\"%s\" />\n" % (operation, node.terminal))

    outfile.close()
    outfile_xml.write("</operations>\n")
    outfile_xml.close()

def get_ios_major_version(release):
    """
    Returns major version of release
    """
    return int(release.split('.')[0])

def is_ios_more_than_10_release(release):
    """
    Returns True if release is using newer (iOS >= 10) binary sandbox profile format.
    """
    major_version = get_ios_major_version(release)
    if major_version < 10:
        return False
    return True


def warn_if_unvalidated(release):
    """Warn when reversing a release newer than the last validated one.

    SandBlaster's binary-format handling has been validated up to
    LAST_VALIDATED_MAJOR. Newer releases (iOS 15 .. 27) are parsed with the
    iOS 13+ code path on a best-effort basis. This keeps the tool usable for
    new firmware while being honest that the layout has not been confirmed.
    """
    major = get_ios_major_version(release)
    if major > LAST_VALIDATED_MAJOR:
        logger.warning(
            "iOS %d has not been validated; using the iOS 13+ format path "
            "(last validated: iOS %d).", major, LAST_VALIDATED_MAJOR)
        print(
            "warning: iOS %d is newer than the last validated release "
            "(iOS %d).\n"
            "         Reversing with the iOS 13+ binary-format path on a "
            "best-effort basis.\n"
            "         If the collection fails to parse it may be in the "
            "newer \"protobox\" format; extract it with\n"
            "         `ipsw sb dump --type protobox <kernelcache>` and file "
            "the format details upstream."
            % (major, LAST_VALIDATED_MAJOR), file=sys.stderr)


def display_sandbox_profiles(f, re_table_offset, num_sb_ops, ios_version):
    logger.info("Printing sandbox profiles from bundle")
    if ios_version >= 13:
        f.seek(6)
    elif ios_version >= 12:
        f.seek(12)
    elif ios_version >= 10:
        f.seek(10)
    else:
        f.seek(6)
    num_profiles = struct.unpack("<H", f.read(2))[0]

    if ios_version >= 13:
        f.seek(2)
        num_operation_nodes = struct.unpack("<H", f.read(2))[0]
        print(hex(num_operation_nodes))
    else:
        # Place file pointer to start of operation nodes area.
        if ios_version >= 12:
            f.seek(14 + (num_sb_ops + 2) * 2 * num_profiles)
        elif ios_version >= 10:
            f.seek(12 + (num_sb_ops + 2) * 2 * num_profiles)
        else:
            f.seek(8 + (num_sb_ops + 2) * 2 * num_profiles)
        while True:
            word = struct.unpack("<H", f.read(2))[0]
            if word != 0:
                f.seek(-2, 1)
                break
        start = f.tell()
        end = re_table_offset * 8
        num_operation_nodes = (end - start) // 8

    logger.info("number of operation nodes: %u" % num_operation_nodes)

    for i in range(0, num_profiles):
        if ios_version >= 13:
            f.seek(8)
            regex_table_count = struct.unpack('<H', f.read(2))[0]
            f.seek(10)
            global_table_count = struct.unpack('<B', f.read(1))[0]
            f.seek(11)
            debug_table_count = struct.unpack('<B', f.read(1))[0]
            f.seek(12 + (regex_table_count + global_table_count + \
                    debug_table_count) * 2 + (num_sb_ops + 2) * 2 * i)
        elif ios_version >= 12:
            f.seek(14 + (num_sb_ops + 2) * 2 * i)
        elif ios_version >= 10:
            f.seek(12 + (num_sb_ops + 2) * 2 * i)
        else:
            f.seek(8 + (num_sb_ops + 2) * 2 * i)

        name_offset = struct.unpack("<H", f.read(2))[0]
        boundary = struct.unpack("<H", f.read(2))[0]
        name = extract_string_from_offset(f, name_offset, ios_version)

        print(name)

    logger.info("Found %d sandbox profiles." % num_profiles)


def get_global_vars(f, vars_offset, num_vars, base_offset):
    global_vars = []
    for i in range(0, num_vars):
        if base_offset > 0:
            f.seek(vars_offset + i*2)
        else:
            f.seek(vars_offset*8 + i*2)
        current_offset = struct.unpack("<H", f.read(2))[0]
        f.seek(base_offset + current_offset * 8)
        if base_offset > 0:
            len = struct.unpack("<H", f.read(2))[0]
        else:
            len = struct.unpack("<I", f.read(4))[0]
        s = f.read(len-1)
        global_vars.append(s)
    logger.info("global variables are {:s}".format(", ".join(
        s.decode("ascii", "replace") if isinstance(s, bytes) else str(s)
        for s in global_vars)))
    return global_vars

def get_base_addr(f, ios_version):
    if ios_version >= 15 and is_modern_format(f):
        return parse_modern_header(f)["base_addr"]
    if ios_version >= 13:
        # extract operation node table count
        f.seek(2)
        op_nodes_count = struct.unpack('<H', f.read(2))[0]

        # extract sandbox operations count
        f.seek(4)
        sb_ops_count = struct.unpack('<H', f.read(2))[0]

        # extract sandbox profile count
        f.seek(6)
        sb_profiles_count = struct.unpack('<H', f.read(2))[0]

        # extract regular expressions count
        f.seek(8)
        regex_table_count = struct.unpack('<H', f.read(2))[0]

        # extract global table count
        f.seek(10)
        global_table_count = struct.unpack('<B', f.read(1))[0]

        # extract debug table count
        f.seek(11)
        debug_table_count = struct.unpack('<B', f.read(1))[0]

        return 12 + (regex_table_count + global_table_count + debug_table_count)*2 \
                + (2 + sb_ops_count) * 2 * sb_profiles_count + op_nodes_count * 8 + 4
    return 0


def main():
    """Reverse Apple binary sandbox file to SBPL (Sandbox Profile Language) format.

    Sample run:
        python reverse_sandbox.py -r 7.1.1 container.sb.bin
        python reverse_sandbox.py -r 7.1.1 -d out container.sb.bin
        python reverse_sandbox.py -r 7.1.1 -d out container.sb.bin -n network-inbound network-outbound
        python reverse_sandbox.py -r 9.0.2 -d out sandbox_bundle_iOS_9.0 -n network-inbound network-outbound -p container
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="path to the binary sandbox profile")
    parser.add_argument("-r", "--release", help="iOS release version for sandbox profile (supported: 4 - 27)", required=True)
    parser.add_argument("-o", "--operations_file", help="file with list of operations", required=True)
    parser.add_argument("-p", "--profile", nargs='+', help="profile to reverse (for bundles) (default is to reverse all operations)")
    parser.add_argument("-n", "--operation", nargs='+', help="particular operation(s) to reverse (default is to reverse all operations)")
    parser.add_argument("-d", "--directory", help="directory where to write reversed profiles (default is current directory)")
    parser.add_argument("-psb", "--print_sandbox_profiles", action="store_true", help="print sandbox profiles of a given bundle (only for iOS versions 9+)")
    parser.add_argument("-kbf", "--keep_builtin_filters", help="keep builtin filters in output", action="store_true")

    args = parser.parse_args()

    if args.filename is None:
        parser.print_usage()
        print("no sandbox profile/bundle file to reverse")
        sys.exit(1)

    warn_if_unvalidated(args.release)

    # Read sandbox operations.
    sb_ops = [l.strip() for l in open(args.operations_file)]
    num_sb_ops = len(sb_ops)
    logger.info("num_sb_ops: %d", num_sb_ops)

    ops_to_reverse = []
    if args.operation:
        for op in args.operation:
            if op not in sb_ops:
                parser.print_usage()
                print("unavailable operation: {}".format(op))
                sys.exit(1)
            ops_to_reverse.append(op)

    if args.directory:
        out_dir = args.directory
    else:
        out_dir = os.getcwd()

    f = open(args.filename, "rb")

    ios_major = get_ios_major_version(args.release)

    # Modern (iOS 15+) collections use a different header and table layout.
    modern = None
    if ios_major >= 15 and is_modern_format(f):
        modern = parse_modern_header(f)
        logger.info("modern collection (format 0x%x): %d profiles, %d operation "
                    "nodes, %d regexes, %d operations, base_addr 0x%x",
                    modern["version"], modern["profiles_count"],
                    modern["op_nodes_count"], modern["regex_count"],
                    modern["num_sb_ops"], modern["base_addr"])
        # The KEXT's operation name table carries more names than the
        # collection has operations (the trailing ones are message-filter
        # operations, a separate namespace), so keep the leading ones.
        if num_sb_ops > modern["num_sb_ops"]:
            logger.info("using the first %d of %d operations from %s",
                        modern["num_sb_ops"], num_sb_ops, args.operations_file)
            sb_ops = sb_ops[:modern["num_sb_ops"]]
            num_sb_ops = len(sb_ops)
        elif num_sb_ops < modern["num_sb_ops"]:
            print("error: collection defines %d operations but %s lists only %d"
                  % (modern["num_sb_ops"], args.operations_file, num_sb_ops),
                  file=sys.stderr)
            sys.exit(1)

    f.seek(0)
    if ios_major >= 6:
        header = struct.unpack("<H", f.read(2))[0]
        logger.debug("header: 0x%x", header)
    else:
        logger.debug("header: none for iOS <6; using 0")
        header = 0

    if modern:
        re_table_offset = modern["regex_table"]
        re_table_count = modern["regex_count"]
    else:
        if ios_major >= 13:
            re_table_offset = 12
        else:
            re_table_offset = struct.unpack("<H", f.read(2))[0]

        if ios_major >= 12:
            f.seek(8)
        re_table_count = struct.unpack("<H", f.read(2))[0]

    logger.debug("re_table_offset: 0x%x", re_table_offset)
    logger.debug("re_table_count: 0x%x", re_table_count)

    logger.debug("\n\nregular expressions:\n")
    regex_list = []
    if re_table_count > 0:
        if get_ios_major_version(args.release) >= 13:
            f.seek(re_table_offset)
        else:
            f.seek(re_table_offset * 8)
        
        re_offsets_table = struct.unpack("<%dH" % re_table_count, f.read(2 * re_table_count))
        for offset in re_offsets_table:
            if get_ios_major_version(args.release) >= 13:
                f.seek(get_base_addr(f, get_ios_major_version(args.release)) + offset * 8)
                re_length = struct.unpack("<H", f.read(2))[0]
            else:
                f.seek(offset * 8)
                re_length = struct.unpack("<I", f.read(4))[0]
            
            re = struct.unpack("<%dB" % re_length, f.read(re_length))
            logger.debug("total_re_length: 0x%x", re_length)
            re_debug_str = "re: [", ", ".join([hex(i) for i in re]), "]"
            logger.debug(re_debug_str)
            regex_list.append(sandbox_regex.parse_regex(re))
    logger.debug(regex_list)

    if args.print_sandbox_profiles:
        if header == 0x8000:
            display_sandbox_profiles(f, re_table_offset, num_sb_ops, get_ios_major_version(args.release))
        else:
            print("cannot print sandbox profiles list; filename {} is not a sandbox bundle".format(args.filename))
        sys.exit(0)

    global_vars = None

    # In case of sandbox profile bundle, go through each profile.
    if header == 0x8000:
        logger.info("using profile bundle")
        if modern:
            vars_offset = modern["global_table"]
            num_vars = modern["global_count"]
            logger.info("{:d} global vars at offset 0x{:0x}".format(num_vars, vars_offset))
            global_vars = get_global_vars(f, vars_offset, num_vars,
                                          modern["base_addr"])
        elif get_ios_major_version(args.release) >= 13:
            # get the regex table entries
            f.seek(8)
            regex_table_count = struct.unpack('<H', f.read(2))[0]
            vars_offset = 12 + regex_table_count * 2
            f.seek(10)
            num_vars = struct.unpack("<B", f.read(1))[0]
            logger.info("{:d} global vars at offset 0x{:0x}".format(num_vars, vars_offset))
            global_vars = get_global_vars(f, vars_offset, num_vars, get_base_addr(f, get_ios_major_version(args.release)))
            f.seek(6)
        elif get_ios_major_version(args.release) >= 12:
            f.seek(4)
            vars_offset = struct.unpack("<H", f.read(2))[0]
            f.seek(10)
            num_vars = struct.unpack("<B", f.read(1))[0]
            logger.info("{:d} global vars at offset 0x{:0x}".format(num_vars, vars_offset))
            global_vars = get_global_vars(f, vars_offset, num_vars, 0)
            f.seek(12)
        elif get_ios_major_version(args.release) >= 10:
            f.seek(6)
            vars_offset = struct.unpack("<H", f.read(2))[0]
            num_vars = struct.unpack("<H", f.read(2))[0]
            logger.info("{:d} global vars at offset 0x{:0x}".format(num_vars, vars_offset))
            global_vars = get_global_vars(f, vars_offset, num_vars, 0)
            f.seek(10)
        else:
            f.seek(6)

        if modern:
            num_profiles = modern["profiles_count"]
        else:
            num_profiles = struct.unpack("<H", f.read(2))[0]
        logger.info("number of profiles in bundle: %d", num_profiles)

        if modern:
            num_operation_nodes = modern["op_nodes_count"]
            f.seek(modern["op_nodes_offset"])
        elif get_ios_major_version(args.release) >= 13:
            f.seek(2)
            num_operation_nodes = struct.unpack("<H", f.read(2))[0]
            f.seek(get_base_addr(f, get_ios_major_version(args.release)) - num_operation_nodes*8)
        else:
            # Place file pointer to start of operation nodes area.
            if get_ios_major_version(args.release) >= 12:
                f.seek(14 + (num_sb_ops + 2) * 2 * num_profiles)
            elif get_ios_major_version(args.release) >= 10:
                f.seek(12 + (num_sb_ops + 2) * 2 * num_profiles)
            else:
                f.seek(8 + (num_sb_ops + 2) * 2 * num_profiles)
            while True:
                word = struct.unpack("<H", f.read(2))[0]
                if word != 0:
                    f.seek(-2, 1)
                    break
            start = f.tell()
            end = re_table_offset * 8
            num_operation_nodes = (end - start) // 8
        logger.info("number of operation nodes: %u" % num_operation_nodes)

        operation_nodes = create_operation_nodes(f, regex_list,
            num_operation_nodes, get_ios_major_version(args.release),
            args.keep_builtin_filters, global_vars)

        for i in range(0, num_profiles):
            if modern:
                f.seek(modern["profile_table"] + MODERN_PROFILE_ENTRY_SIZE * i)
            elif get_ios_major_version(args.release) >= 13:
                f.seek(8)
                regex_table_count = struct.unpack('<H', f.read(2))[0]
                f.seek(10)
                global_table_count = struct.unpack('<B', f.read(1))[0]
                f.seek(11)
                debug_table_count = struct.unpack('<B', f.read(1))[0]
                f.seek(12 + (regex_table_count + global_table_count + \
                        debug_table_count) * 2 + (num_sb_ops + 2) * 2 * i)
            elif get_ios_major_version(args.release) >= 12:
                f.seek(14 + (num_sb_ops + 2) * 2 * i)
            elif get_ios_major_version(args.release) >= 10:
                f.seek(12 + (num_sb_ops + 2) * 2 * i)
            else:
                f.seek(8 + (num_sb_ops + 2) * 2 * i)

            name_offset = struct.unpack("<H", f.read(2))[0]
            boundary = struct.unpack("<H", f.read(2))[0]
            name = extract_string_from_offset(f, name_offset,
                                get_ios_major_version(args.release))

            # Go past profiles not in list, in case list is defined.
            if args.profile:
                if name not in args.profile:
                    continue
            logger.info("profile name (offset 0x%x): %s" % (name_offset, name))

            if modern:
                f.seek(modern["profile_table"] + MODERN_PROFILE_ENTRY_SIZE * i
                       + MODERN_PROFILE_OP_TABLE_OFFSET)
            elif get_ios_major_version(args.release) >= 13:
                f.seek(8)
                regex_table_count = struct.unpack('<H', f.read(2))[0]
                f.seek(10)
                global_table_count = struct.unpack('<B', f.read(1))[0]
                f.seek(11)
                debug_table_count = struct.unpack('<B', f.read(1))[0]
                f.seek(12 + (regex_table_count + global_table_count + \
                        debug_table_count) * 2 + (num_sb_ops + 2) * 2 * i + 4)
            elif get_ios_major_version(args.release) >= 12:
                f.seek(14 + (num_sb_ops + 2) * 2 * i + 4)
            elif get_ios_major_version(args.release) >= 10:
                f.seek(12 + (num_sb_ops + 2) * 2 * i + 4)
            else:
                f.seek(8 + (num_sb_ops + 2) * 2 * i + 4)
            op_table = struct.unpack("<%dH" % num_sb_ops, f.read(2 * num_sb_ops))
            for idx in range(1, len(op_table)):
                offset = op_table[idx]
                operation = sb_ops[idx]
                logger.info("operation %s (index %u) starts at node offset %u (0x%x)", operation, idx, offset, offset)
            out_fname = os.path.join(out_dir, name + ".sb")
            process_profile(f, out_fname, sb_ops, ops_to_reverse, op_table, operation_nodes)

    else:
        if get_ios_major_version(args.release) >= 12:
            f.seek(4)
            vars_offset = struct.unpack("<H", f.read(2))[0]
            f.seek(10)
            num_vars = struct.unpack("<B", f.read(1))[0]
            logger.info("{:d} global vars at offset 0x{:0x}".format(num_vars, vars_offset))
            global_vars = get_global_vars(f, vars_offset, num_vars, 0)
            f.seek(12)
        elif get_ios_major_version(args.release) >= 10:
            f.seek(6)
            vars_offset = struct.unpack("<H", f.read(2))[0]
            num_vars = struct.unpack("<H", f.read(2))[0]
            logger.info("{:d} global vars at offset 0x{:0x}".format(num_vars, vars_offset))
            global_vars = get_global_vars(f, vars_offset, num_vars, 0)
            f.seek(10)
        elif get_ios_major_version(args.release) >= 6:
            f.seek(6)
        else:
            f.seek(4)
        op_table = struct.unpack("<%dH" % num_sb_ops, f.read(2 * num_sb_ops))
        for idx in range(1, len(op_table)):
            offset = op_table[idx]
            operation = sb_ops[idx]
            logger.info("operation %s (index %u) starts at node offset %u (0x%x)", operation, idx, offset, offset)

        # Place file pointer to start of operation nodes area.
        while True:
            word = struct.unpack("<H", f.read(2))[0]
            if word != 0:
                f.seek(-2, 1)
                break
        start = f.tell()
        end = re_table_offset * 8
        num_operation_nodes = (end - start) // 8
        logger.info("number of operation nodes: %d ; start: %#x" % (num_operation_nodes, start))

        operation_nodes = create_operation_nodes(f, regex_list,
            num_operation_nodes, get_ios_major_version(args.release),
            args.keep_builtin_filters, global_vars)
        out_fname = os.path.join(out_dir, os.path.splitext(os.path.basename(args.filename))[0])
        process_profile(f, out_fname, sb_ops, ops_to_reverse, op_table, operation_nodes)

    f.close()


if __name__ == "__main__":
    sys.exit(main())
