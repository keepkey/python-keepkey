"""Find text on a DebugLink OLED frame.

DebugLinkState.layout is the display framebuffer -- 256x64, one bit per pixel,
each byte eight vertical pixels with the least significant bit on top -- and
there is no text channel. So a test that must know WHAT a screen says renders
the expected string with the firmware's own glyphs and looks for exactly those
pixels: every ink pixel of every glyph lit, every other pixel of its cell dark.

The glyph tables below are the title and body fonts of keepkey-firmware
lib/board/font.c (printable ASCII). Regenerate them after a font change with

    python oled_text.py path/to/keepkey-firmware/lib/board/font.c

A body is found the way confirm() draws it: broken into lines as
draw_string_walk() in lib/board/draw.c breaks them (a 44-character Solana
address always wraps), each line whole -- nothing drawn just before or after
it -- and the lines left-aligned on consecutive rows of ONE screen. A body
that pages is not found; assert each page's part instead.
"""

from __future__ import print_function

import re
import sys

GLYPH_HEIGHT = 10
BODY_WIDTH = 225  # layout.h BODY_WIDTH, the wrap width of confirm() bodies
BODY_LINE_PITCH = GLYPH_HEIGHT + 4  # font height + BODY_FONT_LINE_PADDING


def _font(table):
    """'w:rows' per printable character from 0x20, rows as fixed-width hex
    with bit i = column i."""
    glyphs = {}
    for i, entry in enumerate(table.split()):
        width, rows = entry.split(':')
        n = len(rows) // GLYPH_HEIGHT
        glyphs[chr(0x20 + i)] = (int(width), tuple(
            int(rows[r * n:(r + 1) * n], 16) for r in range(GLYPH_HEIGHT)))
    assert len(glyphs) == 95
    return glyphs


# Generated from keepkey-firmware lib/board/font.c by this module's __main__.
TITLE_FONT = _font("""
5:000000000000000000000000000000 3:000003003003003003000003000000 5:00000f00f000000000000000000000 8:00003607f03603607f036000000000
7:00c03e00f00f01e03c03c01f00c000 9:0000c606f03601806c0f6063000000 8:00000e01b01b00e07b03307e000000 3:000003003000000000000000000000
4:006003003003003003003003006000 4:003006006006006006006006003000 7:00c03f01e03f00c000000000000000 7:00000000c00c03f00c00c000000000
4:000000000000000000007007006003 7:00000000000003f000000000000000 4:000000000000000000007007000000 9:0000c006003001800c006003000000
7:00001e03303b03f03703301e000000 4:000007006006006006006006000000 7:00001f03003001e00300303f000000 7:00001f03003001e03003001f000000
7:00001801c01e01b03f018018000000 7:00003f00300301f03003001f000000 7:00001e00300301f03303301e000000 7:00003f03001801800c00c006000000
7:00001e03303301e03303301e000000 7:00001e03303303e03003001e000000 4:000000000007007000007007000000 4:000000000007007000007007006003
6:00001800c00600300600c018000000 7:00000000003f00003f000000000000 6:00000300600c01800c006003000000 7:00001e03303001800c00000c000000
9:07c0c61bb1e31fb1ef0fb00607c000 7:00001e03303303f033033033000000 7:00001f03303301f03303301f000000 7:00001e03300300300303301e000000
7:00001f03303303303303301f000000 7:00003f00300301f00300303f000000 7:00003f00300301f003003003000000 7:00001e03300303b03303303e000000
7:00003303303303f033033033000000 5:00000f00600600600600600f000000 7:00003003003003003003301e000000 7:00003301b00f00700f01b033000000
7:00000300300300300300303f000000 9:0000c30e70ff0db0c30c30c3000000 7:00003303303703f03b033033000000 7:00001e03303303303303301e000000
7:00001f03303303301f003003000000 7:00001e03303303303303301e030000 7:00001f03303303301f01b033000000 7:00001e03300301e03003301e000000
7:00003f00c00c00c00c00c00c000000 7:00003303303303303303301e000000 7:00003303303303301e01e00c000000 9:0000db0db0db0db0db0db07e000000
7:00003303301e00c01e033033000000 7:00003303303301e00c00c00c000000 7:00003f03001800c00600303f000000 5:00000f00300300300300300f000000
9:00000300600c0180300600c0000000 5:00000f00c00c00c00c00c00f000000 5:00000600f000000000000000000000 7:00000000000000000000003f000000
4:000003006000000000000000000000 7:00000000001e03003e03303e000000 7:00000300301f03303303301f000000 7:00000000003e00300300303e000000
7:00003003003e03303303303e000000 7:00000000001e03303f00303e000000 6:00001c00601f006006006006000000 7:00000000003e03303303303e03001e
7:00000300301f033033033033000000 3:000003000003003003003003000000 4:000006000006006006006006006003 6:00000300301b00f00700f01b000000
3:000003003003003003003003000000 9:00000000007f0db0db0db0db000000 7:00000000001f033033033033000000 7:00000000001e03303303301e000000
7:00000000001f03303303301f003003 7:00000000003e03303303303e030030 6:00000000001f007003003003000000 7:00000000003e00301e03001f000000
6:00000600601f00600600601c000000 7:00000000003303303303303e000000 7:00000000003303301e01e00c000000 9:0000000000db0db0db0db07e000000
7:00000000003301e00c01e033000000 7:00000000003303303303303e03001e 7:00000000003f01800c00603f000000 6:00001c00600600300600601c000000
3:000003003003003003003003000000 6:00000700c00c01800c00c007000000 7:00003e01f000000000000000000000
""")

BODY_FONT = _font("""
4:00000000000000000000 2:00010101010100010000 4:00050500000000000000 7:00123f12123f12000000
6:041e05050e14140f0400 8:00422512082452210000 7:000609090629112e0000 2:00010100000000000000
3:02010101010101010200 3:01020202020202020100 6:04150e15040000000000 6:000004041f0404000000
3:00000000000003030201 6:000000001f0000000000 3:00000000000003030000 8:00402010080402010000
6:000e11191513110e0000 3:00030202020202020000 6:000f10100e01011f0000 6:000f10100e10100f0000
6:00080c0a091f08080000 6:001f01010f10100f0000 6:000e01010f11110e0000 6:001f1008080404020000
6:000e11110e11110e0000 6:000e11111e10100e0000 3:00000003030003030000 3:00000003030003030201
5:00080402010204080000 6:0000001f001f00000000 5:00010204080402010000 6:000e1110080400040000
8:3c4299a1b9a579023c00 6:000e11111f1111110000 6:000f11110f11110f0000 6:000e11010101110e0000
6:000f11111111110f0000 6:001f01010f01011f0000 6:001f01010f0101010000 6:000e11011d11111e0000
6:001111111f1111110000 4:00070202020202070000 6:001010101010110e0000 6:00110905030509110000
6:000101010101011f0000 8:00416355494141410000 6:00111113151911110000 6:000e11111111110e0000
6:000f1111110f01010000 6:000e11111111110e1000 6:000f1111110f09110000 6:000e11010e10110e0000
6:001f0404040404040000 6:001111111111110e0000 6:00111111110a0a040000 8:00494949494949360000
6:0011110a040a11110000 6:001111110a0404040000 6:001f10080402011f0000 4:00070101010101070000
8:00010204081020400000 4:00070404040404070000 4:00020500000000000000 6:000000000000001f0000
3:00010200000000000000 6:0000000e101e111e0000 6:0001010f1111110f0000 6:0000001e0101011e0000
6:0010101e1111111e0000 6:0000000e111f011e0000 5:000c020f020202020000 6:0000001e1111111e100e
6:0001010f111111110000 2:00010001010101010000 3:00020002020202020201 5:00010109050305090000
2:00010101010101010000 8:0000003f494949490000 6:0000000f111111110000 6:0000000e1111110e0000
6:0000000f1111110f0101 6:0000001e1111111e1010 5:0000000d030101010000 6:0000001e010e100f0000
5:0002020f0202020c0000 6:000000111111111e0000 6:00000011110a0a040000 8:00000049494949360000
6:000000110a040a110000 6:000000111111111e100e 6:0000001f0804021f0000 5:000c02020102020c0000
2:00010101010101010000 5:00030404080404030000 7:00404020201214080000
""")


def wrap(text, font=BODY_FONT, width=BODY_WIDTH):
    """The lines draw_string_walk() breaks `text` into."""
    lines, line, x = [], '', 0
    for i, c in enumerate(text):
        if c == '\n':
            lines.append(line)
            line, x = '', 0
            continue
        word = font[c][0]
        if c == ' ':
            for n in text[i + 1:]:
                if n in ' \n':
                    break
                word += font[n][0]
        if x + word > width:
            lines.append(line)
            line, x = '', 0
        if x == 0 and c == ' ':
            continue
        line += c
        x += font[c][0]
    lines.append(line)
    return lines


def _rows(layout):
    rows = [0] * 64
    for x in range(256):
        for band in range(8):
            byte = layout[x + band * 256]
            if not isinstance(byte, int):
                byte = ord(byte)
            for bit in range(8):
                if byte >> bit & 1:
                    rows[band * 8 + bit] |= 1 << x
    return rows


def _render(line, font):
    rows, x = [0] * GLYPH_HEIGHT, 0
    for c in line:
        width, glyph = font[c]
        for r in range(GLYPH_HEIGHT):
            rows[r] |= glyph[r] << x
        x += width
    return x, rows


def _at(rows, want, width, x, y, whole):
    """`want` drawn at (x, y); if `whole`, with nothing lit within a glyph's
    width on either side of it (a longer line is not this line)."""
    mask = (1 << width) - 1
    if any((rows[y + r] >> x) & mask != want[r] for r in range(GLYPH_HEIGHT)):
        return False
    if not whole:
        return True
    before = min(x, 9)
    edges = ((1 << before) - 1) << (x - before) | 0x1ff << (x + width)
    return not any(rows[y + r] & edges for r in range(GLYPH_HEIGHT))


def find_line(layout, line, font=BODY_FONT):
    """(x, y) of the topmost rendering of `line` (a prefix of a longer line
    counts), or None."""
    width, want = _render(line, font)
    rows = _rows(layout)
    for y in range(64 - GLYPH_HEIGHT + 1):
        for x in range(256 - width + 1):
            if _at(rows, want, width, x, y, False):
                return x, y
    return None


def shows(layout, text, font=BODY_FONT, width=BODY_WIDTH):
    """Whether this screen shows `text` as confirm() draws a body."""
    lines = [_render(line, font) for line in wrap(text, font, width)]
    rows = _rows(layout)
    height = (len(lines) - 1) * BODY_LINE_PITCH + GLYPH_HEIGHT
    for y in range(64 - height + 1):
        for x in range(256 - lines[0][0] + 1):
            if all(_at(rows, want, w, x, y + i * BODY_LINE_PITCH, True)
                   for i, (w, want) in enumerate(lines)):
                return True
    return False


def find_text(screens, text, font=BODY_FONT, width=BODY_WIDTH, start=0):
    """Index of the first screen from `start` that shows `text`, or None."""
    for i in range(start, len(screens)):
        if shows(screens[i], text, font, width):
            return i
    return None


def _generate(font_c):
    src = open(font_c).read()
    data = {m.group(1): [int(v, 16) for v in
                         re.findall(r'0x([0-9a-fA-F]{2})', m.group(2))]
            for m in re.finditer(
                r'static const uint8_t (image_data_\w+)\[[^\]]*\]\s*=\s*'
                r'\{([^}]*)\}', src)}
    images = {m.group(1): (m.group(2), int(m.group(3)), int(m.group(4)))
              for m in re.finditer(
                  r'static const CharacterImage (\w+)\s*=\s*\{\s*(\w+),\s*'
                  r'(\d+),\s*(\d+)\s*\}', src)}
    out = {}
    for name in ('title_font', 'body_font'):
        array = re.search(r'static const Character %s_array\[\]\s*=\s*\{(.*?)'
                          r'\n\};' % name, src, re.S).group(1)
        glyphs = {}
        for code, image in re.findall(r'\{\s*(0x[0-9a-fA-F]+)\s*,\s*&(\w+)\s*\}',
                                      array):
            if not 0x20 <= int(code, 16) <= 0x7e:
                continue
            pixels, width, height = images[image]
            assert height == GLYPH_HEIGHT, image
            ink = data[pixels]
            assert len(ink) == width * height, image
            glyphs[int(code, 16)] = (width, [
                sum(1 << x for x in range(width) if ink[y * width + x] == 0)
                for y in range(height)])
        assert sorted(glyphs) == list(range(0x20, 0x7f)), name
        digits = (max(w for w, _ in glyphs.values()) + 3) // 4
        entries = ['%d:%s' % (w, ''.join('%0*x' % (digits, r) for r in rows))
                   for w, rows in (glyphs[c] for c in range(0x20, 0x7f))]
        out[name] = '\n'.join(' '.join(entries[i:i + 4])
                              for i in range(0, len(entries), 4))
    return out


if __name__ == '__main__':
    tables = _generate(sys.argv[1])
    print('TITLE_FONT = _font("""\n%s\n""")\n' % tables['title_font'])
    print('BODY_FONT = _font("""\n%s\n""")' % tables['body_font'])
