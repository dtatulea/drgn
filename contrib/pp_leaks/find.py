#!/usr/bin/env drgn

"""
Search page references in kernel memory. This only works if the kernel was built
with CONFIG_PROC_KCORE=y.
"""

import argparse
import math

from drgn import (
        Object,
        PlatformFlags,
        Object,
        offsetof,
        sizeof,
)
from drgn.helpers.common.memory import (
        identify_address,
        print_annotated_memory,
)
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.mm import (
        for_each_vmap_area,
        virt_to_page,
        page_to_virt,
)


byteorder = "little" if prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN else "big"
PAGE_SIZE = prog["PAGE_SIZE"].value_()
PAGE_SHIFT = prog["PAGE_SHIFT"].value_()


def get_opts():
    parser = argparse.ArgumentParser(
        description="Search kernel memory for references to regions in a page or reference to a page."
    )
    parser.add_argument(
        "bytes",
        nargs="?",
        help="hexadecimal bytes to read",
    )
    parser.add_argument(
        "-r", "--raw", default=False, action='store_true',
        help="Search for page reference directly.")
    parser.add_argument(
        "--peek-skb-linear", default=False, action='store_true',
        help="Try to peek as skb linear")
    parser.add_argument(
        "--peek-shinfo", default=False, action='store_true',
        help="Try to peek as shinfo linear")

    return parser.parse_args()


def virt_to_vmap_address(prog, addr):
    page = virt_to_page(addr)
    for va in for_each_vmap_area(prog):
        vm = va.vm.read_()
        if vm:
            for i, va_page in enumerate(
                Object(
                    prog, prog.array_type(page.type_, vm.nr_pages), address=vm.pages
                ).read_()
            ):
                if va_page == page:
                    return (
                        va.va_start.value_()
                        + (i << prog["PAGE_SHIFT"])
                        + (addr & (prog["PAGE_SIZE"].value_() - 1))
                    )
    return None


def search_memory(prog, needle):
    KCORE_RAM = prog["KCORE_RAM"]
    CHUNK_SIZE = 1024 * 1024

    for kc in list_for_each_entry(
        "struct kcore_list", prog["kclist_head"].address_of_(), "list"
    ):
        if kc.type != KCORE_RAM:
            continue
        start = kc.addr.value_()
        end = start + kc.size.value_()
        for addr in range(start, end, CHUNK_SIZE):
            buf = prog.read(addr, min(CHUNK_SIZE, end - addr))
            i = 0
            while i < len(buf):
                i = buf.find(needle, i)
                if i < 0:
                    break

                yield addr + i
                i += 8
                #i += 1


def search_page_reference(page):

    val = page_to_virt(page).value_()

    skip_bytes = math.ceil(PAGE_SHIFT / 8)
    ptr_size = 8

    val_endian = val.to_bytes(ptr_size, byteorder)
    if byteorder == "little":
        big_needle = val_endian[skip_bytes:ptr_size - skip_bytes]
    else:
        big_needle = val_endian[0:ptr_size - skip_bytes]

    small_needle = val >> PAGE_SHIFT

    results = []

    # Search for first 6 bytes:
    for addr in search_memory(prog, big_needle):

        if byteorder == "little":
            # Adjust address to skipped bytes:
            addr = addr - skip_bytes

        mem_bytes = prog.read(addr, ptr_size)
        mem_val = int.from_bytes(mem_bytes, byteorder)

        if mem_val >> PAGE_SHIFT == small_needle:
            results.append((addr, mem_val))

    return results


def search_raw(value):

    ptr_size = 8
    needle = val.to_bytes(ptr_size, byteorder)

    results = []
    for addr in search_memory(prog, needle):
        mem_bytes = prog.read(addr, ptr_size)
        mem_val = int.from_bytes(mem_bytes, byteorder)
        results.append((addr, mem_val))

    return results


opts = get_opts()

if opts.bytes.startswith("0x"):
    opts.bytes = opts.bytes[2:]

val = int.from_bytes(bytes.fromhex(opts.bytes))

if opts.raw:
    results = search_raw(val)
else:
    results = search_page_reference(virt_to_page(val))

for addr, val in results:

    vmap_address = virt_to_vmap_address(prog, addr)
    if vmap_address is not None:
        identity = identify_address(prog, vmap_address)
    else:
        identity = identify_address(prog, addr)

    if identity is None:
        identity = ""

    print(f"Found reference at {hex(addr)}: value {hex(val)}. {identity}")

    if opts.peek_skb_linear:
        len = offsetof(prog.type('struct sk_buff'), "head") + 2 * 8
        print_annotated_memory(addr - offsetof(prog.type('struct sk_buff'), "head"), len)
    elif opts.peek_shinfo:
        len = offsetof(prog.type('struct sk_buff'), "head") + 2 * 8

        head_len = offsetof(prog.type("struct skb_shared_info"), "frags")
        len = sizeof(prog.type("struct skb_shared_info"))
        print_annotated_memory(addr - 2*head_len, len)
