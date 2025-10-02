from binaryninja import PluginCommand, interaction
from binaryninja.log import log_info
import struct

def _to_bytes_literal(b: bytes) -> str:
    return "b'" + ''.join(f"\\x{c:02x}" for c in b) + "'"

def _format_outputs(addr: int):
    p32 = struct.pack('<I', addr & 0xFFFFFFFF)
    p64 = struct.pack('<Q', addr & 0xFFFFFFFFFFFFFFFF)
    return {
        'addr': addr,
        'hex': hex(addr),
        'p32_bytes': p32,
        'p32_py': _to_bytes_literal(p32),
        'p32_hex_escape': ''.join(f"\\x{c:02x}" for c in p32),
        'p64_bytes': p64,
        'p64_py': _to_bytes_literal(p64),
        'p64_hex_escape': ''.join(f"\\x{c:02x}" for c in p64),
    }

def _func_name_for_addr(bv, addr):
    f = bv.get_function_at(addr)
    if f is None:
        fs = bv.get_functions_containing(addr)
        if fs:
            f = fs[0]
    return f.name if f else None

def _log_view(bv, addr):
    out = _format_outputs(addr)
    fname = _func_name_for_addr(bv, addr)
    header = f"{fname} @ {out['hex']}" if fname else f"Address {out['hex']}"
    log_info(f"[pack] {header}")

    addr_size = getattr(bv.arch, "address_size", 0)
    if addr_size == 4:
        log_info(f"[p32] {out['p32_py']}   escaped: {out['p32_hex_escape']}")
    elif addr_size == 8:
        log_info(f"[p64] {out['p64_py']}   escaped: {out['p64_hex_escape']}")
    else:
        log_info(f"[p32] {out['p32_py']}   escaped: {out['p32_hex_escape']}")
        log_info(f"[p64] {out['p64_py']}   escaped: {out['p64_hex_escape']}")

def _show_report(bv, addr):
    out = _format_outputs(addr)
    fname = _func_name_for_addr(bv, addr)
    title = f"p32/p64 for 0x{addr:x}"
    header = f"{fname} @ {out['hex']}" if fname else f"Address {out['hex']}"

    text = (
        f"{header}\n\n"
        f"p32 (4 bytes, little-endian):\n{out['p32_py']}\n"
        f"escaped: {out['p32_hex_escape']}\n\n"
        f"p64 (8 bytes, little-endian):\n{out['p64_py']}\n"
        f"escaped: {out['p64_hex_escape']}\n"
    )
    interaction.show_plain_text_report(title, text)


PluginCommand.register_for_address(
    "Pack 32/64: View in Log",
    "Log p32/p64 forms to the console without a popup.",
    _log_view,
)

PluginCommand.register_for_address(
    "Pack 32/64: Show Report",
    "Open a plain-text report with p32/p64 forms.",
    _show_report,
)
