"""
stego_utils.py
--------------
Bit-level LSB-style steganography.

The carrier file is treated as one long stream of bits (MSB first in each
byte). Starting at bit S, every L-th bit is overwritten with the next bit of
[64-bit payload length][payload]. In "cycle" mode L steps through a list of
gaps (e.g. 8,16,28,8) instead of staying constant.

Because the payload length is stored in the first 64 replaced bits, the
payload size does not need to be known when extracting.
"""
from pathlib import Path


class SteganographyError(Exception):
    """Raised for any steganography problem (bad parameters, too large, ...)."""


# Payload length is stored as an unsigned 64-bit integer.
HEADER_BITS = 64

# Safety valve so tiny cycle gaps on huge files can't exhaust memory.
MAX_POSITIONS = 64_000_000


# ---------------------------------------------------------------------------
# Small helpers (kept for compatibility / testing)
# ---------------------------------------------------------------------------

def bytes_to_bits(data: bytes):
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        raise SteganographyError("The extracted bit stream is not byte-aligned.")
    result = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = (value << 1) | bit
        result.append(value)
    return bytes(result)


def integer_to_bits(value, number_of_bits=64):
    if value < 0:
        raise SteganographyError("Payload size cannot be negative.")
    if value > (1 << number_of_bits) - 1:
        raise SteganographyError("Payload is too large.")
    return [(value >> i) & 1 for i in range(number_of_bits - 1, -1, -1)]


def bits_to_integer(bits):
    if not bits:
        raise SteganographyError("No bits were supplied.")
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _get_bit(buf, position):
    return (buf[position >> 3] >> (7 - (position & 7))) & 1


def _set_bit(buf, position, bit):
    index = position >> 3
    mask = 0x80 >> (position & 7)
    if bit:
        buf[index] |= mask
    else:
        buf[index] &= ~mask & 0xFF


# ---------------------------------------------------------------------------
# Parameters and positions
# ---------------------------------------------------------------------------

def validate_parameters(start_bit, period):
    if start_bit < 0:
        raise SteganographyError("Starting bit S must be zero or greater.")
    if period <= 0:
        raise SteganographyError("Period L must be greater than zero.")


def get_period_generator(mode, period, cycle_values=None):
    if mode == "fixed":
        while True:
            yield period

    elif mode == "cycle":
        if not cycle_values:
            raise SteganographyError("Cycle mode requires at least one period value.")
        values = []
        for value in cycle_values:
            value = int(value)
            if value <= 0:
                raise SteganographyError("Cycle periods must be greater than zero.")
            values.append(value)
        index = 0
        while True:
            yield values[index]
            index = (index + 1) % len(values)

    else:
        raise SteganographyError(f"Unknown mode: {mode}")


def get_replacement_positions(carrier_bit_length, start_bit, period,
                              mode="fixed", cycle_values=None):
    """
    Return the carrier bit positions that are modified (indexable, sized).
    Fixed mode returns a lazy range; cycle mode returns a list.
    """
    validate_parameters(start_bit, period)

    if start_bit >= carrier_bit_length:
        return []

    if mode == "fixed":
        return range(start_bit, carrier_bit_length, period)

    positions = []
    current = start_bit
    gaps = get_period_generator(mode, period, cycle_values)

    while current < carrier_bit_length:
        positions.append(current)
        if len(positions) > MAX_POSITIONS:
            raise SteganographyError(
                "The chosen cycle values touch too many bits. Use larger gaps."
            )
        current += next(gaps)

    return positions


def calculate_capacity(carrier_size_bytes, start_bit, period,
                       mode="fixed", cycle_values=None):
    positions = get_replacement_positions(
        carrier_size_bytes * 8, start_bit, period, mode, cycle_values
    )
    if len(positions) <= HEADER_BITS:
        return 0
    return (len(positions) - HEADER_BITS) // 8


# ---------------------------------------------------------------------------
# Embedding / extraction on bytes
# ---------------------------------------------------------------------------

def embed_bytes(carrier_data, message_data, start_bit, period,
                mode="fixed", cycle_values=None):
    """Layout: [64-bit payload size][payload]."""
    buf = bytearray(carrier_data)

    positions = get_replacement_positions(
        len(buf) * 8, start_bit, period, mode, cycle_values
    )

    required_bits = HEADER_BITS + len(message_data) * 8
    if required_bits > len(positions):
        capacity = max(0, (len(positions) - HEADER_BITS) // 8)
        raise SteganographyError(
            "Message is too large for the carrier. "
            f"Maximum payload capacity is approximately {capacity} bytes."
        )

    # Header + payload as one bit sequence.
    def all_bits():
        for bit in integer_to_bits(len(message_data), HEADER_BITS):
            yield bit
        for byte in message_data:
            for i in range(7, -1, -1):
                yield (byte >> i) & 1

    for bit, position in zip(all_bits(), positions):
        _set_bit(buf, position, bit)

    return bytes(buf)


def extract_message_size(stego_data, start_bit, period,
                         mode="fixed", cycle_values=None):
    positions = get_replacement_positions(
        len(stego_data) * 8, start_bit, period, mode, cycle_values
    )

    if len(positions) < HEADER_BITS:
        raise SteganographyError(
            "The carrier does not contain a complete payload-size header."
        )

    header_bits = [_get_bit(stego_data, positions[i]) for i in range(HEADER_BITS)]
    message_size = bits_to_integer(header_bits)

    maximum_possible_size = max(0, len(positions) - HEADER_BITS) // 8
    if message_size > maximum_possible_size:
        raise SteganographyError(
            "Invalid payload size stored in the stego file. The S/L/C "
            "parameters may be incorrect or the file may not have been "
            "generated by this application."
        )

    return message_size


def extract_bytes(stego_data, start_bit, period, mode="fixed", cycle_values=None):
    positions = get_replacement_positions(
        len(stego_data) * 8, start_bit, period, mode, cycle_values
    )

    message_size = extract_message_size(
        stego_data, start_bit, period, mode, cycle_values
    )

    out = bytearray(message_size)
    base = HEADER_BITS
    for bit_index in range(message_size * 8):
        if _get_bit(stego_data, positions[base + bit_index]):
            out[bit_index >> 3] |= 0x80 >> (bit_index & 7)

    return bytes(out)


# ---------------------------------------------------------------------------
# File wrappers
# ---------------------------------------------------------------------------

def embed_file(carrier_path, message_path, output_path, start_bit, period,
               mode="fixed", cycle_values=None):
    carrier_data = Path(carrier_path).read_bytes()
    message_data = Path(message_path).read_bytes()

    result = embed_bytes(carrier_data, message_data, start_bit, period,
                         mode, cycle_values)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(result)

    return {
        "carrier_size": len(carrier_data),
        "message_size": len(message_data),
        "output_size": len(result),
        "capacity": calculate_capacity(len(carrier_data), start_bit, period,
                                       mode, cycle_values),
    }


def extract_file(stego_path, output_message_path, start_bit, period,
                 mode="fixed", cycle_values=None):
    stego_data = Path(stego_path).read_bytes()

    message_data = extract_bytes(stego_data, start_bit, period, mode, cycle_values)

    output_message_path = Path(output_message_path)
    output_message_path.parent.mkdir(parents=True, exist_ok=True)
    output_message_path.write_bytes(message_data)

    return {"message_size": len(message_data)}
