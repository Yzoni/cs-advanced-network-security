def bit_enabled(octal, bit_num):
    if (octal & (1 << bit_num)) != 0:
        return True
    else:
        return False


def parse_4_bit_opcode(octal):
    op_code = 0

    if (octal & (1 << 6)) != 0:
        op_code += 0b1

    if (octal & (1 << 5)) != 0:
        op_code += 0b01

    if (octal & (1 << 4)) != 0:
        op_code += 0b001

    if (octal & (1 << 3)) != 0:
        op_code += 0b0001

    return op_code

def parse_4_bit_rcode(octal):
    rc_code = 0

    if (octal & (1 << 3)) != 0:
        rc_code += 0b1

    if (octal & (1 << 2)) != 0:
        rc_code += 0b01

    if (octal & (1 << 1)) != 0:
        rc_code += 0b001

    if (octal & (1 << 0)) != 0:
        rc_code += 0b0001

    return rc_code