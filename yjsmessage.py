# Yjs Websocket Message Decoder/Builder
# Usage: python yjsmessage.py decode <base64>  or  python yjsmessage.py build
# Interactive: python yjsmessage.py
# example input AAIYAQGox+XYAe0fhKjH5dgB7B8FaGVsbG8A48uh6gvMhIrE7jM=    AAIYAQGox+XYAfIfhKjH5dgB8R8FaGVsbG8A48uh6gvMhIrE7jM=

import base64
import sys

# ---- varint helpers ----

def encode_varint(value: int) -> bytes:
    buf = []
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            byte |= 0x80
        buf.append(byte)
        if not value:
            break
    return bytes(buf)


def decode_varint(data: bytes, offset: int = 0):
    value = 0
    shift = 0
    start = offset
    while offset < len(data):
        byte = data[offset]
        value |= (byte & 0x7f) << shift
        shift += 7
        offset += 1
        if not (byte & 0x80):
            break
    return value, offset, (offset - start)


# ---- builder ----

TAIL = bytes.fromhex("e3cba1ea0bcc848ac4ee33")


def build_raw(client_id: int, clock: int, content: str, tail: bytes = TAIL,
              marker: int = 0x84, struct_meta: int = 0, struct_ref: int = 0,
              info_byte: int = 0x18) -> bytes:
    content_bytes = content.encode('utf-8')
    msg = bytearray([0x00, 0x02, info_byte, 0x01, 0x01])
    msg += encode_varint(client_id)
    msg += encode_varint(clock)
    msg.append(marker)
    msg += encode_varint(client_id)
    if marker == 0xc4:
        msg += encode_varint(struct_meta)
        msg += encode_varint(struct_ref)
    msg += encode_varint(clock - 1)
    msg += encode_varint(len(content_bytes))
    msg += content_bytes
    msg.append(0x00)
    msg += tail
    return bytes(msg)


def build_yjs_update(client_id, clock, content: str, tail: bytes = TAIL):
    return build_raw(client_id, clock, content, tail)


def build_b64(client_id: int, clock: int, content: str, tail: bytes = TAIL,
              marker: int = 0x84, struct_meta: int = 0, struct_ref: int = 0,
              info_byte: int = 0x18) -> str:
    raw = build_raw(client_id, clock, content, tail, marker, struct_meta, struct_ref, info_byte)
    return base64.b64encode(raw).decode()


# ---- parser ----

FIELD_NAMES = {
    'msg_type': 'Message type',
    'num_structs': 'Number of structs',
    'info_byte': 'Content type / info byte',
    'field_a': 'Header field A (always 1)',
    'field_b': 'Header field B (always 1)',
    'client_id': 'Author client ID',
    'clock': 'Insert position (clock)',
    'marker': 'Struct marker / ref client start',
    'client_id2': 'Ref client ID',
    'struct_meta': 'Struct metadata (unknown)',
    'struct_ref': 'Ref clock (fixed ref)',
    'clock2': 'Clock B (struct end)',
    'str_len': 'Content length',
    'content': 'Content (UTF-8)',
    'null_marker': 'Null terminator',
    'tail': 'State vector tail',
}


def parse_fields(data: bytes):
    fields = []
    ofs = 0

    msg_type, ofs, n = decode_varint(data, ofs)
    fields.append(('msg_type', msg_type, n))

    num_structs, ofs, n = decode_varint(data, ofs)
    fields.append(('num_structs', num_structs, n))

    info_byte, ofs, n = decode_varint(data, ofs)
    fields.append(('info_byte', info_byte, n))

    field_a, ofs, n = decode_varint(data, ofs)
    fields.append(('field_a', field_a, n))

    field_b, ofs, n = decode_varint(data, ofs)
    fields.append(('field_b', field_b, n))

    client_id, ofs, n = decode_varint(data, ofs)
    fields.append(('client_id', client_id, n))

    clock, ofs, n = decode_varint(data, ofs)
    fields.append(('clock', clock, n))

    marker = data[ofs]
    fields.append(('marker', marker, 1))
    ofs += 1

    client_id2, ofs, n = decode_varint(data, ofs)
    fields.append(('client_id2', client_id2, n))

    # Additional fields after struct2 client vary by marker type
    if marker == 0x84:
        clock2, ofs, n = decode_varint(data, ofs)
        fields.append(('clock2', clock2, n))
    elif marker == 0xc4:
        extra_meta, ofs, n = decode_varint(data, ofs)
        fields.append(('struct_meta', extra_meta, n))
        extra_ref, ofs, n = decode_varint(data, ofs)
        fields.append(('struct_ref', extra_ref, n))
        clock2, ofs, n = decode_varint(data, ofs)
        fields.append(('clock2', clock2, n))
    else:
        clock2, ofs, n = decode_varint(data, ofs)
        fields.append(('clock2', clock2, n))

    str_len, ofs, n = decode_varint(data, ofs)
    fields.append(('str_len', str_len, n))

    if ofs + str_len > len(data):
        raise ValueError(f"Content length {str_len} exceeds remaining data {len(data) - ofs}")

    content_bytes = data[ofs:ofs + str_len]
    fields.append(('content', content_bytes, str_len))
    ofs += str_len

    if ofs >= len(data):
        raise ValueError(f"Ran past end of data (offset {ofs}) before null terminator")
    null_marker = data[ofs]
    fields.append(('null_marker', null_marker, 1))
    ofs += 1

    tail = data[ofs:]
    fields.append(('tail', tail, len(tail)))

    return fields


def parse_b64(b64_string: str):
    try:
        data = base64.b64decode(b64_string)
    except Exception as e:
        print(f"[!] Invalid base64: {e}")
        return None
    return parse_fields(data)


def pretty_print(fields):
    for key, value, nbytes in fields:
        label = FIELD_NAMES.get(key, key)

        if isinstance(value, bytes):
            if key == 'content':
                try:
                    display = value.decode('utf-8')
                except UnicodeDecodeError:
                    display = value.hex()
            elif key == 'tail':
                display = value.hex()
            else:
                display = value.hex()
        else:
            display = str(value)

        if isinstance(value, int):
            hex_part = f"  (0x{value:02x})" if value < 256 else ""
            print(f"  [{nbytes:2d}b] {label:30s} = {display}{hex_part}")
        else:
            print(f"  [{nbytes:2d}b] {label:30s} = {display}")


# ---- decode from CLI ----

def cmd_decode(args):
    b64 = args[0] if args else input("Base64 string: ").strip()
    print(f"\n--- Parsing Yjs message ---")
    fields = parse_b64(b64)
    if fields:
        pretty_print(fields)
    else:
        return

    # Summary
    clock = None
    client_id = None
    content = None
    for k, v, _ in fields:
        if k == 'clock': clock = v
        if k == 'client_id': client_id = v
        if k == 'content':
            try: content = v.decode('utf-8')
            except: content = v.hex()

    if clock is not None and client_id is not None:
        print(f"\n  --- Summary ---")
        print(f"  Client ID: {client_id}")
        print(f"  Clock:     {clock}")
        if content:
            print(f"  Content:   {content}")


# ---- forge core (byte-level reconstruction) ----

def _skip_varint(data: bytes, offset: int):
    while offset < len(data) and (data[offset] & 0x80):
        offset += 1
    return offset + 1


def forge_message(data: bytes, new_content: str, *,
                  override_clock: int = None, override_client_id: int = None,
                  override_ref_client: int = None, override_clock2: int = None):
    null_pos = len(data) - 12

    # Find str_len position by working backwards from null
    str_len_pos = None
    for sl in range(1, min(256, null_pos)):
        candidate = null_pos - sl - 1
        if candidate >= 0 and data[candidate] == sl:
            str_len_pos = candidate
            break
    if str_len_pos is None:
        raise ValueError("Could not locate content boundary")

    old_str_len = data[str_len_pos]
    old_content = data[str_len_pos + 1 : str_len_pos + 1 + old_str_len]

    # Find client_id: starts at offset 5
    orig_client_id, client_id_end, _ = decode_varint(data, 5)

    # Find clock: starts after client_id
    orig_clock, clock_end, _ = decode_varint(data, client_id_end)

    marker = data[clock_end]

    # Determine values (override or auto)
    actual_client_id = override_client_id if override_client_id is not None else orig_client_id
    actual_clock = override_clock if override_clock is not None else (orig_clock + len(new_content))
    new_str_len = len(new_content)
    new_content_bytes = new_content.encode('utf-8')

    new_client_id_enc = encode_varint(actual_client_id)
    new_clock_enc = encode_varint(actual_clock)

    forged = bytearray()
    forged.extend(data[:5])        # fixed header bytes
    forged.extend(new_client_id_enc)  # author client ID
    forged.extend(new_clock_enc)      # clock

    if marker == 0x84:
        ref_start = clock_end + 1
        orig_ref_client, ref_end, _ = decode_varint(data, ref_start)
        actual_ref_client = override_ref_client if override_ref_client is not None else orig_ref_client
        forged.append(marker)
        forged.extend(encode_varint(actual_ref_client))
        if override_clock2 is not None:
            forged.extend(encode_varint(override_clock2))
        else:
            forged.extend(encode_varint(actual_clock - 1))
    else:
        # 0xc4 and others: preserve all bytes between clock_end and str_len_pos verbatim
        forged.extend(data[clock_end:str_len_pos])

    forged.append(new_str_len)
    forged.extend(new_content_bytes)
    forged.extend(data[str_len_pos + 1 + old_str_len:])

    return bytes(forged), old_content, orig_clock, actual_clock, orig_client_id, actual_client_id


def _prompt_field(label: str, auto_value, value_type: type = int):
    """Prompt user for a field value. Return auto_value if nothing entered."""
    prompt = f"  {label} (default: {auto_value}): "
    raw = input(prompt).strip()
    if not raw:
        return auto_value
    try:
        return value_type(raw)
    except ValueError:
        print(f"    Invalid {value_type.__name__}, using default: {auto_value}")
        return auto_value


def cmd_forgenext(args):
    b64 = args[0] if args else input("Base64: ").strip()
    content_override = args[1] if len(args) > 1 else None
    no_prompt = len(args) >= 2  # skip interactive if both b64 and content given on CLI

    data = base64.b64decode(b64)

    # Show decoded fields for reference
    print()
    try:
        fields = parse_fields(data)
        if fields:
            pretty_print(fields)
    except Exception as e:
        print(f"[!] Could not fully decode: {e}")
        print(f"    raw hex: {data.hex()}")

    msg_type, _, _ = decode_varint(data, 0)
    if msg_type != 0:
        print(f"[!] Message type {msg_type} is not yet supported by forgenext.")
        print(f"    This tool currently only supports message type 0 (sync step 1).")
        print(f"    Base64: {b64}")
        print(f"    Hex:    {data.hex()}")
        return

    # Extract positions using byte-level approach
    try:
        null_pos = len(data) - 12
        str_len_pos = None
        for sl in range(1, min(256, null_pos)):
            candidate = null_pos - sl - 1
            if candidate >= 0 and data[candidate] == sl:
                str_len_pos = candidate
                break
        if str_len_pos is None:
            raise ValueError("Could not locate content boundary")
        old_content = data[str_len_pos + 1 : str_len_pos + 1 + data[str_len_pos]]
        try:
            old_content_str = old_content.decode('utf-8')
        except UnicodeDecodeError:
            old_content_str = old_content.hex()

        # Parse client_id and clock for display
        orig_client_id, cid_end, _ = decode_varint(data, 5)
        orig_clock, clock_end, _ = decode_varint(data, cid_end)
        marker = data[clock_end]
    except Exception as e:
        print(f"[!] {e}")
        return

    if content_override is not None:
        new_content = content_override
    else:
        new_content = input(f"  Content (default: '{old_content_str}'): ").strip()
        if not new_content:
            new_content = old_content_str

    # Common: find ref_client position for override
    ref_start = clock_end + 1
    orig_ref_client, ref_end, _ = decode_varint(data, ref_start)

    # Interactive field-by-field override (skip when both args given on CLI)
    if not no_prompt:
        print(f"\n  --- Field overrides (Enter = use auto value) ---")

        auto_clock = orig_clock + len(new_content)
        use_client_id = _prompt_field("Author client ID", orig_client_id)
        use_ref_client = _prompt_field("Ref client ID", orig_ref_client)
        use_clock = _prompt_field("Clock", auto_clock)

        if marker == 0x84:
            auto_clock2 = use_clock - 1
            _, old_clock2, _ = decode_varint(data, ref_end)
            use_clock2 = _prompt_field("Clock B (clock-1)", auto_clock2)
        else:
            use_clock2 = None
    else:
        use_client_id = orig_client_id
        use_ref_client = orig_ref_client
        use_clock = orig_clock + len(new_content)
        use_clock2 = None

    try:
        forged, old_c, old_clk, new_clk, old_cid, new_cid = forge_message(
            data, new_content,
            override_client_id=use_client_id,
            override_ref_client=use_ref_client,
            override_clock=use_clock,
            override_clock2=use_clock2,
        )
    except Exception as e:
        print(f"[!] Forge failed: {e}")
        return

    print(f"\n  --- Forged result ---")
    print(f"  Client ID: {old_cid} -> {new_cid}")
    print(f"  Clock:     {old_clk} -> {new_clk}")
    print(f"  Content:   '{old_content_str}' ({len(old_c)}B) -> '{new_content}' ({len(new_content)}B)")

    b64_out = base64.b64encode(forged).decode()
    print(f"\n  Forged base64: {b64_out}")
    print(f"  Hex:           {forged.hex()}")


def cmd_edit(args):
    """Decode a message and let the user edit each field individually, keeping original values as defaults."""
    b64 = args[0] if args else input("Base64: ").strip()

    data = base64.b64decode(b64)

    # Show decoded fields
    print()
    try:
        fields = parse_fields(data)
        if fields:
            pretty_print(fields)
    except Exception as e:
        print(f"[!] Could not fully decode: {e}")
        print(f"    raw hex: {data.hex()}")

    msg_type, _, _ = decode_varint(data, 0)
    if msg_type != 0:
        print(f"[!] Message type {msg_type} is not yet supported for editing.")
        print(f"    This tool currently only supports message type 0 (sync step 1).")
        print(f"    Base64: {b64}")
        print(f"    Hex:    {data.hex()}")
        return

    try:
        null_pos = len(data) - 12
        str_len_pos = None
        for sl in range(1, min(256, null_pos)):
            candidate = null_pos - sl - 1
            if candidate >= 0 and data[candidate] == sl:
                str_len_pos = candidate
                break
        if str_len_pos is None:
            raise ValueError("Could not locate content boundary")

        orig_client_id, cid_end, _ = decode_varint(data, 5)
        orig_clock, clock_end, _ = decode_varint(data, cid_end)
        marker = data[clock_end]

        old_content = data[str_len_pos + 1 : str_len_pos + 1 + data[str_len_pos]]
        try:
            old_content_str = old_content.decode('utf-8')
        except UnicodeDecodeError:
            old_content_str = old_content.hex()

        ref_start = clock_end + 1
        orig_ref_client, ref_end, _ = decode_varint(data, ref_start)

        orig_clock2 = None
        if marker == 0x84:
            orig_clock2, _, _ = decode_varint(data, ref_end)
    except Exception as e:
        print(f"[!] Byte-level analysis failed: {e}")
        return

    # Prompt for content (default = existing)
    print(f"\n  --- Edit fields (Enter = keep current value) ---")
    use_content = input(f"  Content (default: '{old_content_str}'): ").strip()
    if not use_content:
        use_content = old_content_str

    # Field prompts with original values as defaults
    use_client_id = _prompt_field("Author client ID", orig_client_id)
    use_ref_client = _prompt_field("Ref client ID", orig_ref_client)
    use_clock = _prompt_field("Clock", orig_clock)

    use_clock2 = None
    if marker == 0x84 and orig_clock2 is not None:
        use_clock2 = _prompt_field("Clock B", orig_clock2)

    try:
        forged, old_c, old_clk, new_clk, old_cid, new_cid = forge_message(
            data, use_content,
            override_client_id=use_client_id,
            override_ref_client=use_ref_client,
            override_clock=use_clock,
            override_clock2=use_clock2,
        )
    except Exception as e:
        print(f"[!] Edit failed: {e}")
        return

    print(f"\n  --- Edited result ---")
    print(f"  Client ID: {old_cid} -> {new_cid}")
    print(f"  Clock:     {old_clk} -> {new_clk}")
    print(f"  Content:   '{old_content_str}' ({len(old_c)}B) -> '{use_content}' ({len(use_content)}B)")

    b64_out = base64.b64encode(forged).decode()
    print(f"\n  Base64: {b64_out}")
    print(f"  Hex:    {forged.hex()}")


# ---- build from CLI ----

def cmd_build(args):
    import io
    client_id = int(input("Client ID: "))
    clock = int(input("Clock: "))
    content = input("Content string: ")
    tail_hex = input("Tail hex (or enter for default): ").strip()
    tail = bytes.fromhex(tail_hex) if tail_hex else TAIL

    raw = build_raw(client_id, clock, content, tail)
    b64 = base64.b64encode(raw).decode()
    print(f"\nBase64: {b64}")


# ---- main ----

def interactive():
    print("Yjs Message Tool - Interactive")
    print("Commands: decode | build | forgenext | edit | help | quit")
    while True:
        try:
            cmd = input("\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd:
            continue
        if cmd in ('q', 'quit', 'exit'):
            break
        elif cmd in ('d', 'decode'):
            b64 = input("Base64: ").strip()
            fields = parse_b64(b64)
            if fields:
                pretty_print(fields)
        elif cmd in ('b', 'build'):
            try:
                client_id = int(input("Client ID: "))
                clock = int(input("Clock: "))
                content = input("Content: ")
                tail_hex = input("Tail hex (default): ").strip()
                tail = bytes.fromhex(tail_hex) if tail_hex else TAIL
                raw = build_raw(client_id, clock, content, tail)
                print(f"\nBase64: {base64.b64encode(raw).decode()}")
                print(f"Hex:    {raw.hex()}")
            except ValueError as e:
                print(f"[!] Invalid input: {e}")
        elif cmd in ('f', 'forgenext'):
            cmd_forgenext([])
        elif cmd in ('e', 'edit'):
            cmd_edit([])
        elif cmd in ('h', 'help'):
            print("  decode    - Decode a base64 Yjs message")
            print("  build     - Build a Yjs message from scratch")
            print("  forgenext - Decode, auto-adjust clock, edit content, re-encode")
            print("  edit      - Decode and edit any field (Enter = keep existing)")
            print("  quit      - Exit")
        else:
            print("Unknown command. Try: decode, build, forgenext, edit, help, quit")


if __name__ == '__main__':
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        args = sys.argv[2:]
        if cmd == 'decode':
            cmd_decode(args)
        elif cmd == 'build':
            cmd_build(args)
        elif cmd in ('forgenext', 'forge'):
            cmd_forgenext(args)
        elif cmd in ('edit', 'e'):
            cmd_edit(args)
        elif cmd == 'interactive':
            interactive()
        else:
            print(f"Usage: {sys.argv[0]} [decode|build|forgenext|edit|interactive]")
    else:
        interactive()
