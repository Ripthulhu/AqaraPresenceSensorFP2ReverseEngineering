import argparse
from pathlib import Path
import sys
from .framer import Framer
from .protocol import decode_packet

def parse_line_generator(filename):
    """Generator that yields (channel, data_bytes) tuples from a file."""
    try:
        with open(filename, "r") as f:
            for line in f:
                items = line.strip().split(" ")
                if not items:
                    continue
                # Auto-detect timestamp and ignore it
                if items[0].startswith("t"):
                    items.pop(0)
                    if not items:
                        continue
                
                try:
                    channel = int(items[0])
                    # Optimized hex parsing
                    dps_bytes = bytearray(int(x, 16) for x in items[1:])
                    yield channel, dps_bytes
                except ValueError:
                    continue
    except FileNotFoundError:
        print(f"File not found: {filename}")
        return

def handle_decode(args):
    print(f"\n{'='*20} {args.file} {'='*20}")
    
    xmodem_blocks = {0: [], 1: []}
    xmodem_seen = {0: set(), 1: set()}

    def record_xmodem_block(channel, seq, block_len, payload, crc, marker):
        key = (seq, payload)
        if key in xmodem_seen[channel]:
            return

        xmodem_seen[channel].add(key)
        xmodem_blocks[channel].append((seq, payload, crc, marker))
        if args.show_xmodem:
            marker_name = "SOH" if marker == 0x01 else "STX"
            print(f"[ch{channel}] XMODEM {marker_name} seq={seq:03d} len={block_len} crc={crc.hex()}")

    framers = [
        Framer(0, on_xmodem_block=record_xmodem_block),
        Framer(1, on_xmodem_block=record_xmodem_block),
    ]
    
    # Callback to print packets as they are framed
    def print_packet(channel, packet):
        if args.xmodem_only:
            return
        lines = decode_packet(channel, packet, exclude_names=args.exclude)
        for line in lines:
            print(line)

    for channel, data in parse_line_generator(args.file):
        framers[channel].add(data)
        while framers[channel].packets:
            packet = framers[channel].packets.pop(0)
            print_packet(channel, packet)

    if args.xmodem_out:
        out_base = Path(args.xmodem_out)
        channels_with_data = [ch for ch, blocks in xmodem_blocks.items() if blocks]

        if not channels_with_data:
            print("No XMODEM blocks found.")
            return

        for channel in channels_with_data:
            blocks = xmodem_blocks[channel]
            payload = b"".join(block for _seq, block, _crc, _marker in blocks)
            out_path = out_base
            if len(channels_with_data) > 1:
                out_path = out_base.with_name(f"{out_base.stem}.ch{channel}{out_base.suffix}")
            out_path.write_bytes(payload)
            print(f"Wrote {len(blocks)} XMODEM blocks ({len(payload)} bytes) from channel {channel} to {out_path}")

def handle_sniff(args):
    from .sniffer import run_sniffer
    run_sniffer(args)

def main():
    parser = argparse.ArgumentParser(description="Aqara FP2 Protocol Decoder")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Decode subcommand
    decode_parser = subparsers.add_parser("decode", help="Decode a capture file")
    decode_parser.add_argument("file", help="Path to the capture file")
    decode_parser.add_argument("--exclude", "-x", help="Exclude attributes by name (comma separated)", type=lambda s: s.split(","))
    decode_parser.add_argument("--show-xmodem", action="store_true", help="Print XMODEM block metadata while decoding")
    decode_parser.add_argument("--xmodem-only", action="store_true", help="Suppress decoded protocol packets while collecting XMODEM blocks")
    decode_parser.add_argument("--xmodem-out", help="Write reassembled XMODEM payload bytes to this file")
    decode_parser.set_defaults(func=handle_decode)

    # Sniff subcommand
    sniff_parser = subparsers.add_parser("sniff", help="Sniff UART in real-time (requires Glasgow)")
    sniff_parser.add_argument("--out", "-o", help="Output file for raw capture", default=None)
    sniff_parser.add_argument("--exclude", "-x", help="Exclude attributes by name (comma separated)", type=lambda s: s.split(","))
    sniff_parser.add_argument("--visualize", "-v", help="Open visualization window for target positions", action="store_true")
    # Add Glasgow args if needed, or pass them through
    sniff_parser.set_defaults(func=handle_sniff)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
