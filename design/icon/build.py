#!/usr/bin/env python3
"""macop logo generator.

Concept -- "Enclave": an Apple-silicon chip whose die is a keyhole.
macop's differentiator is not "another password manager" but secrets bound to
Apple hardware: Keychain at the process boundary, Secure Enclave-backed
identities. The mark says exactly that -- silicon (pins + squircle die) holding
a secret (keyhole), with the keyhole in the one warm accent colour so the
"secret" is the focal point.

Everything is generated: no font dependency, no binary source of truth.
Run `python3 build.py` to regenerate every SVG.
"""

import math
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "svg")

# ---------------------------------------------------------------- palette ---
INK        = "#1D1D1F"   # Apple's near-black, wordmark on light

# The public build has one original neutral field. The die and keyway never
# change, and no third-party artwork is used.
THEMES = {
    "spacegrey": {
        "wall": 0.46, "smoke": 0.40,
        "place": "",
        "sky": [(0.0, "#55585F"), (1.0, "#1F2024")],
    },
}
THEME      = os.environ.get("MACOP_THEME", "spacegrey")
_T         = THEMES[THEME]
FIELD      = _T["sky"]
# The die face is smoked glass: the sky shows through it, blurred. Smoke keeps
# the keyway's contrast fixed no matter what the sky is doing -- clear glass
# would put it back at the sky's mercy.
# Smoke opacity is per theme and is not a taste call: it is the lowest value
# that still holds >= 5.5:1 between the keyway and the glass behind it, found by
# sweeping and measuring. `./check-contrast.js` re-runs that measurement, so the
# rule survives a palette edit.
GLASS_SMOKE   = ("#0B0D12", _T["smoke"])   # the window
# The wall's tint is SIGNED, and per theme, and measured rather than judged:
# positive tints the glass white, negative smokes it. Glass is only visible by
# its contrast with what is behind it, so the direction follows the sky --
# white over a dark sky, smoke over a bright one.
GLASS_WALL_LIGHT = max(0.0, _T["wall"])
GLASS_WALL_DARK  = max(0.0, -_T["wall"])
GLASS_BLUR    = 26.0                # backdrop blur behind the die, in icon units
BODY_BLUR     = 14.0                # refraction at the body's own edge
GLASS_MIN_CONTRAST = 5.5    # keyway vs window
DIE_MIN_CONTRAST   = 1.75   # die wall vs the sky beside it
# Die + pins: aluminium, not flat white. The bounce-light stop at the bottom is
# what stops it reading as paper and starts it reading as metal.
METAL      = [(0.0, "#FFFFFF"), (0.16, "#F4F7FC"), (0.52, "#CFD7E4"),
              (0.86, "#A6B0C2"), (1.0, "#C7CFDC")]
# The secret: macOS system orange. Fixed across every theme.
AMBER      = [(0.0, "#FFB340"), (1.0, "#FF9500")]

# ------------------------------------------------------------- primitives ---
def superellipse(cx, cy, half, n=5.0, samples=72, reverse=False):
    """Apple-style squircle (continuous corners) as a closed cubic path.

    Points are resampled to equal arc length before the spline is fitted;
    uniform-t sampling bunches on a high-exponent superellipse and lets the
    Catmull-Rom control points invert on the near-straight sides.
    """
    dense = []
    steps = 4000
    for i in range(steps):
        t = 2.0 * math.pi * i / steps
        ct, st = math.cos(t), math.sin(t)
        dense.append((cx + half * math.copysign(abs(ct) ** (2.0 / n), ct),
                      cy + half * math.copysign(abs(st) ** (2.0 / n), st)))
    cum = [0.0]
    for i in range(1, steps + 1):
        a, b = dense[i - 1], dense[i % steps]
        cum.append(cum[-1] + math.hypot(b[0] - a[0], b[1] - a[1]))
    total, pts, j = cum[-1], [], 0
    for k in range(samples):
        target = total * k / samples
        while cum[j + 1] < target:
            j += 1
        seg = cum[j + 1] - cum[j]
        f = 0.0 if seg == 0 else (target - cum[j]) / seg
        a, b = dense[j], dense[(j + 1) % steps]
        pts.append((a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f))
    # Reversed winding turns the shape into a hole under the nonzero rule, which
    # is what lets it be unioned with some subpaths and subtracted from others in
    # the same path. evenodd cannot do that: it would also punch out wherever two
    # unioned subpaths overlap.
    return catmull_rom_closed(pts[::-1] if reverse else pts)


def catmull_rom_closed(p):
    """Closed Catmull-Rom through `p`, emitted as cubic beziers."""
    n = len(p)
    d = [f"M {p[0][0]:.2f} {p[0][1]:.2f}"]
    for i in range(n):
        p0, p1, p2, p3 = p[(i - 1) % n], p[i], p[(i + 1) % n], p[(i + 2) % n]
        c1 = (p1[0] + (p2[0] - p0[0]) / 6.0, p1[1] + (p2[1] - p0[1]) / 6.0)
        c2 = (p2[0] - (p3[0] - p1[0]) / 6.0, p2[1] - (p3[1] - p1[1]) / 6.0)
        d.append("C %.2f %.2f %.2f %.2f %.2f %.2f" % (c1[0], c1[1], c2[0], c2[1], p2[0], p2[1]))
    d.append("Z")
    return " ".join(d)


def arc(cx, cy, r, a0, a1):
    """Open arc path, angles in degrees, CCW in a y-down space."""
    x0, y0 = cx + r * math.cos(math.radians(a0)), cy - r * math.sin(math.radians(a0))
    x1, y1 = cx + r * math.cos(math.radians(a1)), cy - r * math.sin(math.radians(a1))
    large = 1 if abs(a1 - a0) > 180 else 0
    sweep = 0 if a1 > a0 else 1
    return f"M {x0:.3f} {y0:.3f} A {r} {r} 0 {large} {sweep} {x1:.3f} {y1:.3f}"


# -------------------------------------------------------- the mark: chip ----
# Mark is authored around origin (0,0) at the chip centre.
CHIP_OUTER = 480.0          # chip die, outer edge to outer edge
RING_W     = 62.0           # die wall
CHIP_MID   = (CHIP_OUTER - RING_W) / 2.0   # 214, stroke centreline
PIN_W      = 52.0           # pin thickness
PIN_OUT    = 72.0           # how far a pin reaches past the die
PIN_IN     = 24.0           # how far it tucks under the wall
PIN_OFF    = 132.0          # pin spacing from the side centre
MARK_HALF  = CHIP_OUTER / 2.0 + PIN_OUT    # 312 -> mark bbox 624 x 624

KEY_EYE_R   = 68.0          # eye
KEY_EYE_CY  = -62.0         # eye centre, relative to chip centre
KEY_BOT_Y   = 130.0         # bottom of the ward
KEY_SHIFT   = -6.0          # optical re-centring for the asymmetric profile
# The ward carries a single tooth, low on one side: a warded keyway, the cut
# that makes a lock accept exactly one key. It is also what keeps the mark from
# reading as a head over shoulders -- no symmetric silhouette escapes that.
KEY_WARD   = [(-25, "cy"), (25, "cy"), (25, 46), (52, 46), (52, "by"), (-25, "by")]
KEY_WARD_R = [0, 0, 7, 7, 9, 9]


def chip_ring():
    """The die wall, as a band between two superellipses (evenodd), not a stroke.

    A stroked superellipse's inner edge is NOT another superellipse -- offsetting
    a curve inward does not stay in the family -- so anything meant to sit flush
    inside it (the glass window) leaves a gap at the corners. Defining both edges
    as superellipses makes the seam exact. The wall is RING_W at the sides and a
    little heavier at the corners, which reads as intent, not error.
    """
    return chip_outer() + " " + chip_inner()


def chip_outer():
    # Flatter sides than the app-icon squircle so the pins meet a straight edge.
    return superellipse(0, 0, CHIP_OUTER / 2.0, n=6.0)


def chip_inner():
    """The die window: the ring's inner edge, and the glass panel's outline."""
    return superellipse(0, 0, CHIP_OUTER / 2.0 - RING_W, n=6.0)


def chip_pins():
    """Twelve pins, three per side, as rounded bars."""
    edge = CHIP_OUTER / 2.0
    x0, x1 = edge - PIN_IN, edge + PIN_OUT
    r = PIN_W / 2.0
    out = []
    for off in (-PIN_OFF, 0.0, PIN_OFF):
        # right / left / bottom / top
        out.append((x0, off - r, x1 - x0, PIN_W, r))
        out.append((-x1, off - r, x1 - x0, PIN_W, r))
        out.append((off - r, x0, PIN_W, x1 - x0, r))
        out.append((off - r, -x1, PIN_W, x1 - x0, r))
    return out


def rounded_poly(pts, radii):
    """Closed polygon with a per-vertex corner radius. Wound clockwise."""
    n, d = len(pts), []
    for i in range(n):
        p0, p1, p2 = pts[(i - 1) % n], pts[i], pts[(i + 1) % n]
        v0 = (p0[0] - p1[0], p0[1] - p1[1]); l0 = math.hypot(*v0) or 1.0
        v1 = (p2[0] - p1[0], p2[1] - p1[1]); l1 = math.hypot(*v1) or 1.0
        r = min(radii[i], l0 / 2.0, l1 / 2.0)
        a = (p1[0] + v0[0] * r / l0, p1[1] + v0[1] * r / l0)
        c = (p1[0] + v1[0] * r / l1, p1[1] + v1[1] * r / l1)
        d.append(("M " if i == 0 else "L ") + f"{a[0]:.2f} {a[1]:.2f}"
                 + (f" Q {p1[0]:.2f} {p1[1]:.2f} {c[0]:.2f} {c[1]:.2f}" if r > 0.01 else ""))
    return " ".join(d) + " Z"


def keyhole():
    """Eye union keyway.

    Both subpaths wind clockwise, so the nonzero rule unions them instead of
    punching the overlap out, and the sharp concave shoulder where the eye's
    arc hands over to the ward survives -- the notch a real keyhole has.
    """
    r, cy, by, dx = KEY_EYE_R, KEY_EYE_CY, KEY_BOT_Y, KEY_SHIFT
    eye = (f"M {dx - r:g} {cy:g} a {r:g} {r:g} 0 1 1 {2*r:g} 0 "
           f"a {r:g} {r:g} 0 1 1 {-2*r:g} 0 Z")
    pts = [(x + dx, cy if y == "cy" else by if y == "by" else y) for x, y in KEY_WARD]
    return eye + " " + rounded_poly(pts, KEY_WARD_R)


def mark_group(indent, ring_fill, key_fill):
    """The mark, centred on (0,0). Caller supplies a transform."""
    i = " " * indent
    s = [f'{i}<path d="{chip_ring()}" fill="{ring_fill}" fill-rule="evenodd"/>']
    for x, y, w, h, r in chip_pins():
        s.append(f'{i}<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" rx="{r:g}" fill="{ring_fill}"/>')
    s.append(f'{i}<path d="{keyhole()}" fill="{key_fill}"/>')
    return "\n".join(s)


# --------------------------------------------------------- the wordmark -----
# "macop" drawn as a monoline geometric lowercase: circles, arcs and stems on a
# single stroke weight, matching the mark's own geometric language. No font.
X_HEIGHT = 200.0
STROKE   = 40.0
R_BOWL   = (X_HEIGHT - STROKE) / 2.0     # 77, bowl centreline radius
CY_BOWL  = -X_HEIGHT / 2.0               # -100
R_ARCH   = 62.0                          # 'm' shoulder radius
ARCH_Y   = -(X_HEIGHT - STROKE / 2.0) + R_ARCH   # spring line for 'm'
DESC     = 72.0                          # 'p' descender, below baseline

# outer-edge x positions, optically tracked (flat|round pairs are looser)
LX = {"m": 0.0, "a": 318.0, "c": 544.0, "o": 752.0, "p": 986.0}
WORD_W = 1186.0
WORD_TOP = -X_HEIGHT
WORD_BOT = DESC + STROKE / 2.0


def wordmark_paths():
    d = []
    # m -- stem, shoulder, stem, shoulder, stem
    x = LX["m"] + STROKE / 2.0
    d.append(f"M {x} 0 V {ARCH_Y} A {R_ARCH} {R_ARCH} 0 0 1 {x + 2*R_ARCH} {ARCH_Y} V 0")
    d.append(f"M {x + 2*R_ARCH} {ARCH_Y} A {R_ARCH} {R_ARCH} 0 0 1 {x + 4*R_ARCH} {ARCH_Y} V 0")
    # a -- circle + tangent right stem
    cx = LX["a"] + X_HEIGHT / 2.0
    d.append(circle_path(cx, CY_BOWL, R_BOWL))
    d.append(f"M {cx + R_BOWL} {CY_BOWL - R_BOWL} V 0")
    # c -- open arc
    cx = LX["c"] + X_HEIGHT / 2.0
    d.append(arc(cx, CY_BOWL, R_BOWL, 52, 308))
    # o -- circle
    cx = LX["o"] + X_HEIGHT / 2.0
    d.append(circle_path(cx, CY_BOWL, R_BOWL))
    # p -- circle + tangent left stem carrying the descender
    cx = LX["p"] + X_HEIGHT / 2.0
    d.append(circle_path(cx, CY_BOWL, R_BOWL))
    d.append(f"M {cx - R_BOWL} {CY_BOWL - R_BOWL} V {DESC}")
    return d


def circle_path(cx, cy, r):
    return f"M {cx - r} {cy} a {r} {r} 0 1 0 {2*r} 0 a {r} {r} 0 1 0 {-2*r} 0"


def wordmark_group(indent, color):
    i = " " * indent
    body = "\n".join(f'{i}  <path d="{p}"/>' for p in wordmark_paths())
    return (f'{i}<g fill="none" stroke="{color}" stroke-width="{STROKE}" '
            f'stroke-linecap="round" stroke-linejoin="round">\n{body}\n{i}</g>')


# ------------------------------------------------------------- documents ----
HDR = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}" width="{w}" height="{h}" role="img" aria-label="{label}">'


def _grad_xy(gid, stops, x0, y0, x1, y1):
    body = "".join(f'<stop offset="{o:g}" stop-color="{c}"/>' for o, c in stops)
    return (f'<linearGradient id="{gid}" x1="{x0:g}" y1="{y0:g}" x2="{x1:g}" y2="{y1:g}" '
            f'gradientUnits="userSpaceOnUse">{body}</linearGradient>')


def _grad(gid, stops, y0, y1):
    body = "".join(f'<stop offset="{o:g}" stop-color="{c}"/>' for o, c in stops)
    return (f'<linearGradient id="{gid}" x1="0" y1="{y0:g}" x2="0" y2="{y1:g}" '
            f'gradientUnits="userSpaceOnUse">{body}</linearGradient>')


def _ray(size, apex, x0, x1, fold=0.0):
    """One wedge from the vanishing point out past the bottom edge.

    `fold` shifts this wedge's own apex sideways, so the rays are not all struck
    from one point. That is what makes the fan read as folded facets rather than
    as a flat colour wheel -- and, with the apex off centre, what stops the warm
    core standing dead vertical.
    """
    ax, ay = (apex[0] + fold) * size, apex[1] * size
    y = size * 1.30
    return f"M {ax:g} {ay:g} L {x0*size:g} {y:g} L {x1*size:g} {y:g} Z"


def _arc(size, c):
    """One bowed curve across the frame. Coordinates are fractions of the size."""
    x0, y0, x1, y1, bow = c
    return (f"M {x0*size:g} {y0*size:g} Q {(x0+x1)/2*size:g} "
            f"{((y0+y1)/2 - bow)*size:g} {x1*size:g} {y1*size:g}")


def _above(size, c):
    """Everything above that curve, closed off the top of the frame."""
    return _arc(size, c) + f" L {c[2]*size:g} {-0.2*size:g} L {c[0]*size:g} {-0.2*size:g} Z"


def _ribbon(size, y_left, y_right, bow, thick):
    """One broad translucent plane sweeping edge to edge.

    Drawn past both edges so the clip never reveals an end, and blurred hard
    enough that it reads as light rather than as a shape.
    """
    x0, x1 = -0.12 * size, 1.12 * size
    yl, yr = y_left * size, y_right * size
    cy = (yl + yr) / 2.0 - bow * size
    t = thick * size
    return (f"M {x0:g} {yl:g} Q {size*0.5:g} {cy:g} {x1:g} {yr:g} "
            f"L {x1:g} {yr+t:g} Q {size*0.5:g} {cy+t:g} {x0:g} {yl+t:g} Z")


def _headlands(size, y, back, front):
    """Two coastal ridges, the back one catching the light."""
    w = size
    return [
        (f"M 0 {w*(y+0.030):g} C {w*0.22:g} {w*(y-0.048):g} {w*0.44:g} {w*(y-0.012):g} "
         f"{w*0.66:g} {w*(y+0.006):g} C {w*0.82:g} {w*(y+0.020):g} {w*0.92:g} {w*(y+0.002):g} "
         f"{w} {w*(y-0.012):g} L {w} {w} L 0 {w} Z", back),
        (f"M 0 {w*(y+0.098):g} C {w*0.18:g} {w*(y+0.030):g} {w*0.40:g} {w*(y+0.062):g} "
         f"{w*0.60:g} {w*(y+0.080):g} C {w*0.80:g} {w*(y+0.098):g} {w*0.90:g} {w*(y+0.074):g} "
         f"{w} {w*(y+0.058):g} L {w} {w} L 0 {w} Z", front),
    ]


def background_layer(size=1024):
    """Sky plus landscape. Drawn twice -- once for real, once blurred behind the
    glass. SVG has no backdrop-filter, so the backdrop has to be re-rendered."""
    cx = size / 2.0
    return (f'  <path d="{superellipse(cx, cx, 824.0/2)}" fill="url(#field)"/>\n'
            + landscape_layer(size))


def sky_defs(size):
    """Filters and gradients the release's own sky composition needs."""
    d, cx = [], size / 2.0
    if _T.get("ribbons") or _T.get("rays") or _T.get("split"):
        d.append(f'    <filter id="wide" x="-60%" y="-60%" width="220%" height="220%">'
                 f'<feGaussianBlur stdDeviation="{_T.get("blur", 32.0):g}"/></filter>')
    if _T.get("glow"):
        d.append('    <filter id="blur" x="-50%" y="-50%" width="200%" height="200%">'
                 '<feGaussianBlur stdDeviation="46"/></filter>')
    if not any(_T.get(k) for k in ("ribbons", "rays", "glow", "corners", "split")):
        d.append(f'    <radialGradient id="sheen" cx="{cx}" cy="{size*0.14}" r="{size*0.66}" '
                 f'gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#FFFFFF" '
                 f'stop-opacity="0.16"/><stop offset="1" stop-color="#FFFFFF" '
                 f'stop-opacity="0"/></radialGradient>')
    rays = _T.get("rays")
    if rays and rays.get("glow_r"):
        ax, ay = rays["apex"]
        d.append(f'    <radialGradient id="apex" cx="{ax*size:g}" cy="{ay*size:g}" '
                 f'r="{rays["glow_r"]*size:g}" gradientUnits="userSpaceOnUse">'
                 f'<stop offset="0" stop-color="#FFFFFF" stop-opacity="0.92"/>'
                 f'<stop offset="0.45" stop-color="#FFE7BC" stop-opacity="0.34"/>'
                 f'<stop offset="1" stop-color="#FFE7BC" stop-opacity="0"/></radialGradient>')
    sp = _T.get("split")
    if sp:
        d.append("    " + _grad_xy("above", sp["above"], 0, 0, size, size * 0.30))
        d.append("    " + _grad_xy("below", sp["below"], 0, size * 0.28, 0, size))
        d.append(f'    <linearGradient id="lit" x1="0" y1="{size*0.05:g}" x2="0" y2="{size:g}" '
                 f'gradientUnits="userSpaceOnUse">'
                 f'<stop offset="0" stop-color="#FFFFFF" stop-opacity="0"/>'
                 f'<stop offset="0.5" stop-color="#FFFFFF" stop-opacity="0.8"/>'
                 f'<stop offset="1" stop-color="#FFFFFF" stop-opacity="0"/></linearGradient>')
    for i, (gx, gy, r, col, op) in enumerate(_T.get("corners") or []):
        d.append(f'    <radialGradient id="c{i}" cx="{gx*size:g}" cy="{gy*size:g}" '
                 f'r="{r*size:g}" gradientUnits="userSpaceOnUse">'
                 f'<stop offset="0" stop-color="{col}" stop-opacity="{op:g}"/>'
                 f'<stop offset="0.55" stop-color="{col}" stop-opacity="{op*0.42:g}"/>'
                 f'<stop offset="1" stop-color="{col}" stop-opacity="0"/></radialGradient>')
    return d


def field_defs(size=1024):
    """App-icon field: sky, light, die face, glass edge, and the die's shadow."""
    cx = size / 2.0
    d = ["  <defs>",
         "    " + _grad("field", FIELD, 100.0, 924.0),
         "    " + _grad("metal", METAL, size * 0.21, size * 0.79),
         "    " + _grad("amber", AMBER, size * 0.40, size * 0.66),
              f'    <clipPath id="body"><path d="{superellipse(cx, cx, 824.0/2)}"/></clipPath>',
         '    <filter id="lift" x="-40%" y="-40%" width="180%" height="180%">'
         '<feDropShadow dx="0" dy="12" stdDeviation="15" flood-color="#000000" flood-opacity="0.48"/></filter>',
         f'    <filter id="frost" x="-25%" y="-25%" width="150%" height="150%">'
         f'<feGaussianBlur stdDeviation="{GLASS_BLUR:g}"/></filter>',
         f'    <clipPath id="allglass"><path d="{outer_path(size)} {pins_path(size)}"/></clipPath>',
         f'    <linearGradient id="rim" x1="{size*0.30:g}" y1="{size*0.28:g}" x2="{size*0.72:g}" '
         f'y2="{size*0.74:g}" gradientUnits="userSpaceOnUse">'
         f'<stop offset="0" stop-color="#FFFFFF" stop-opacity="0.98"/>'
         f'<stop offset="0.38" stop-color="#FFFFFF" stop-opacity="0.45"/>'
         f'<stop offset="1" stop-color="#FFFFFF" stop-opacity="0.16"/></linearGradient>',
         f'    <linearGradient id="frame" x1="0" y1="{size*0.21:g}" x2="0" y2="{size*0.79:g}" '
         f'gradientUnits="userSpaceOnUse">'
         f'<stop offset="0" stop-color="#FFFFFF" stop-opacity="{GLASS_WALL_LIGHT:g}"/>'
         f'<stop offset="0.45" stop-color="#FFFFFF" stop-opacity="{GLASS_WALL_LIGHT*0.45:g}"/>'
         f'<stop offset="1" stop-color="#FFFFFF" stop-opacity="{GLASS_WALL_LIGHT*0.78:g}"/></linearGradient>',
         # The union outline: the die's edge except where pins cross it, and the
         # pins' edges except inside the die. Stroking each subpath whole would
         # draw the seams that are supposed to be invisible.
         f'    <clipPath id="outsidedie" clipPathUnits="userSpaceOnUse">'
         f'<path d="M -20 -20 H {size+20} V {size+20} H -20 Z {outer_path(size)}" '
         f'clip-rule="evenodd"/></clipPath>',
         f'    <clipPath id="outsidepins" clipPathUnits="userSpaceOnUse">'
         f'<path d="M -20 -20 H {size+20} V {size+20} H -20 Z {pins_path(size)}" '
         f'clip-rule="evenodd"/></clipPath>',
         f'    <filter id="bodyfrost" x="-30%" y="-30%" width="160%" height="160%">'
         f'<feGaussianBlur stdDeviation="{BODY_BLUR:g}"/></filter>',
         f'    <radialGradient id="edgegrad" cx="0.5" cy="0.5" r="0.58">'
         f'<stop offset="0.52" stop-color="#000000"/>'
         f'<stop offset="0.86" stop-color="#8A8A8A"/>'
         f'<stop offset="1" stop-color="#FFFFFF"/></radialGradient>',
         f'    <mask id="edgemask"><path d="{superellipse(size/2.0, size/2.0, 824.0/2)}" '
         f'fill="url(#edgegrad)"/></mask>',
         f'    <linearGradient id="bodyrim" x1="{size*0.18:g}" y1="0" x2="{size*0.82:g}" y2="{size:g}" '
         f'gradientUnits="userSpaceOnUse">'
         f'<stop offset="0" stop-color="#FFFFFF" stop-opacity="0.58"/>'
         f'<stop offset="0.5" stop-color="#FFFFFF" stop-opacity="0.08"/>'
         f'<stop offset="1" stop-color="#FFFFFF" stop-opacity="0.30"/></linearGradient>',
         f'    <linearGradient id="glasslight" x1="0" y1="{size*0.28:g}" x2="0" y2="{size*0.72:g}" '
         f'gradientUnits="userSpaceOnUse">'
         f'<stop offset="0" stop-color="#FFFFFF" stop-opacity="0.20"/>'
         f'<stop offset="0.45" stop-color="#FFFFFF" stop-opacity="0.02"/>'
         f'<stop offset="1" stop-color="#FFFFFF" stop-opacity="0.10"/></linearGradient>',
         f'    <linearGradient id="sweep" x1="0" y1="{size*0.06:g}" x2="{size*0.52:g}" '
         f'y2="{size*0.66:g}" gradientUnits="userSpaceOnUse">'
         f'<stop offset="0" stop-color="#FFFFFF" stop-opacity="0.16"/>'
         f'<stop offset="0.5" stop-color="#FFFFFF" stop-opacity="0.03"/>'
         f'<stop offset="1" stop-color="#FFFFFF" stop-opacity="0"/></linearGradient>']
    d += sky_defs(size)
    d.append("  </defs>")
    return "\n".join(d)


def landscape_layer(size=1024):
    """The release's own sky, clipped to the icon body."""
    cx, g = size / 2.0, []
    sp = _T.get("split")
    if sp:
        # One curve owns the frame: it divides it into two colour fields, and
        # every other line is bowed differently so none of them run parallel.
        g.append(f'<rect width="{size}" height="{size}" fill="url(#below)"/>')
        g.append(f'<path d="{_above(size, sp["curve"])}" fill="url(#above)"/>')
        for c, col, op, wdt in sp["lines"]:
            a = _arc(size, c)
            g.append(f'<path d="{a}" fill="none" stroke="url(#lit)" stroke-width="{wdt*5:g}" '
                     f'filter="url(#wide)" stroke-opacity="0.55"/>')
            g.append(f'<path d="{a}" fill="none" stroke="{col}" stroke-opacity="{op:g}" '
                     f'stroke-width="{wdt:g}"/>')
    rays = _T.get("rays")
    if rays:
        # Rays first: everything else sits on top of them. One blurred group,
        # not one filter per wedge, so the seams between them stay clean.
        w, n = rays["wedges"], len(rays["wedges"])
        fold = rays.get("fold", 0.0)
        g.append('<g filter="url(#wide)">' + "".join(
            f'<path d="{_ray(size, rays["apex"], x0, x1, (fold if i % 2 else -fold) * (1 - abs(i - n/2.0) / (n/2.0)))}" fill="{col}"/>'
            for i, (x0, x1, col) in enumerate(w)) + "</g>")
        if rays.get("glow_r"):
            g.append(f'<rect width="{size}" height="{size}" fill="url(#apex)"/>')
    for r in (_T.get("ribbons") or []):
        d = _ribbon(size, r["from"], r["to"], r["bow"], r["thick"])
        g.append(f'<path d="{d}" fill="{r["color"]}" fill-opacity="{r["opacity"]:g}" '
                 f'filter="url(#wide)"/>')
        if r.get("edge"):
            # A filled band on its own reads as a gradient, not as glass.
            g.append(f'<path d="{d}" fill="none" stroke="{r["edge"]}" '
                     f'stroke-opacity="{r.get("edge_op", 0.8):g}" '
                     f'stroke-width="{r.get("edge_w", 3.0):g}"/>')
    for i in range(len(_T.get("corners") or [])):
        g.append(f'<rect width="{size}" height="{size}" fill="url(#c{i})"/>')
    if _T.get("glow"):
        gy, gop, gc = _T["glow"]
        g.append(f'<ellipse cx="{cx}" cy="{size*gy:g}" rx="{size*0.46:g}" ry="{size*0.10:g}" '
                 f'fill="{gc}" fill-opacity="{gop}" filter="url(#blur)"/>')
    if _T.get("ridge"):
        back, front = _T["ridge"]
        for path, col in _headlands(size, _T["ridge_y"], back, front):
            g.append(f'<path d="{path}" fill="{col}"/>')
    if not g:
        g.append(f'<rect width="{size}" height="{size}" fill="url(#sheen)"/>')
    return f'  <g clip-path="url(#body)">{"".join(g)}</g>'


ICON_SCALE = 0.94           # the mark's scale inside the icon body


def face_path(size=1024, reverse=False):
    """The die window in icon coordinates -- exactly the ring's inner edge."""
    cx = size / 2.0
    return superellipse(cx, cx, (CHIP_OUTER / 2.0 - RING_W) * ICON_SCALE, n=6.0, reverse=reverse)


def outer_path(size=1024):
    """The die's outer edge in icon coordinates."""
    cx = size / 2.0
    return superellipse(cx, cx, (CHIP_OUTER / 2.0) * ICON_SCALE, n=6.0)


def pins_path(size=1024):
    """The pins in icon coordinates, as path subpaths.

    Subpaths rather than <rect>s so a single nonzero fill unions them with the
    die: separate elements would stack a second layer of tint over every overlap,
    which is exactly what made the joints look wrong.
    """
    cx, out = size / 2.0, []
    for x, y, w, h, r in chip_pins():
        X, Y, W, H, R = cx + x*ICON_SCALE, cx + y*ICON_SCALE, w*ICON_SCALE, h*ICON_SCALE, r*ICON_SCALE
        out.append(f"M {X+R:.2f} {Y:.2f} H {X+W-R:.2f} A {R:.2f} {R:.2f} 0 0 1 {X+W:.2f} {Y+R:.2f} "
                   f"V {Y+H-R:.2f} A {R:.2f} {R:.2f} 0 0 1 {X+W-R:.2f} {Y+H:.2f} H {X+R:.2f} "
                   f"A {R:.2f} {R:.2f} 0 0 1 {X:.2f} {Y+H-R:.2f} V {Y+R:.2f} "
                   f"A {R:.2f} {R:.2f} 0 0 1 {X+R:.2f} {Y:.2f} Z")
    return " ".join(out)


def body_glass(size=1024):
    """The icon body is a glass tile: its edge refracts what is behind it.

    Masked rather than clipped to a band -- a hard boundary reads as a border,
    not as glass.
    """
    body = superellipse(size/2.0, size/2.0, 824.0/2)
    return "\n".join([
        '  <g mask="url(#edgemask)">',
        f'    <g filter="url(#bodyfrost)">{background_layer(size).strip()}</g>',
        f'    <path d="{body}" fill="#FFFFFF" fill-opacity="0.09"/>',
        "  </g>"])


def glass_panel(size=1024):
    """The die as one piece of glass.

    Wall and pins are one shape at one density; only the window is smoked,
    because that is the one place contrast has to be guaranteed. The window is
    wound backwards so the nonzero rule subtracts it while still unioning the
    pins -- evenodd would also punch out every pin/wall overlap. Edges are lit
    rather than filled: without a rim, translucent glass at 32px is a grey smudge.
    """
    outer, window = outer_path(size), face_path(size)
    hole, pins, smoke_c = face_path(size, reverse=True), pins_path(size), GLASS_SMOKE[0]
    cx = size / 2.0
    return "\n".join([
        '  <g filter="url(#lift)">',
        '    <g clip-path="url(#allglass)">',
        f'      <g filter="url(#frost)">{background_layer(size).strip()}</g>',
        (f'      <path d="{outer} {pins} {hole}" fill="{smoke_c}" '
         f'fill-opacity="{GLASS_WALL_DARK:g}"/>' if GLASS_WALL_DARK else "")
        + f'      <path d="{outer} {pins} {hole}" fill="url(#frame)"/>',
        "    </g>",
        f'    <path d="{window}" fill="{smoke_c}" fill-opacity="{GLASS_SMOKE[1]}"/>',
        f'    <path d="{window}" fill="url(#glasslight)"/>',
        f'    <g clip-path="url(#outsidepins)"><path d="{outer}" fill="none" '
        f'stroke="url(#rim)" stroke-width="3.5"/></g>',
        f'    <g clip-path="url(#outsidedie)"><path d="{pins}" fill="none" '
        f'stroke="url(#rim)" stroke-width="2.6"/></g>',
        f'    <path d="{window}" fill="none" stroke="url(#rim)" stroke-width="2.5" stroke-opacity="0.8"/>',
        f'    <g transform="translate({cx} {cx}) scale({ICON_SCALE})">'
        f'<path d="{keyhole()}" fill="url(#amber)"/></g>',
        "  </g>"])


def app_icon():
    size, body = 1024, 824.0
    cx = size / 2.0
    return "\n".join([
        HDR.format(vb=f"0 0 {size} {size}", w=size, h=size, label="macop"),
        field_defs(size),
        background_layer(size),
        body_glass(size),
        glass_panel(size),
        f'  <path d="{superellipse(cx, cx, body/2.0)}" fill="url(#sweep)"/>',
        f'  <path d="{superellipse(cx, cx, body/2.0 - 3)}" fill="none" stroke="url(#bodyrim)" '
        f'stroke-width="5"/>',
        "</svg>"])


def mark_svg(color=True):
    """Mark on its own, transparent, bbox-tight."""
    n = MARK_HALF * 2
    ring = "url(#metal)" if color else "currentColor"
    key = "url(#amber)" if color else "currentColor"
    defs = ""
    if color:
        defs = f'''  <defs>
    <linearGradient id="metal" x1="0" y1="0" x2="0" y2="{n}" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#4A4E57"/><stop offset="1" stop-color="{INK}"/>
    </linearGradient>
    <linearGradient id="amber" x1="0" y1="{n*0.34}" x2="0" y2="{n*0.72}" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="{AMBER[0][1]}"/><stop offset="1" stop-color="{AMBER[1][1]}"/>
    </linearGradient>
  </defs>
'''
    return "\n".join([
        HDR.format(vb=f"0 0 {n:g} {n:g}", w=f"{n:g}", h=f"{n:g}", label="macop"),
        defs.rstrip("\n") if defs else "",
        f'  <g transform="translate({MARK_HALF:g} {MARK_HALF:g})">',
        mark_group(4, ring, key), "  </g>", "</svg>"]).replace("\n\n", "\n")


def wordmark_svg():
    pad = STROKE / 2.0
    w, h = WORD_W, WORD_BOT - WORD_TOP
    return "\n".join([
        HDR.format(vb=f"0 {WORD_TOP:g} {w:g} {h:g}", w=f"{w:g}", h=f"{h:g}", label="macop"),
        wordmark_group(2, "currentColor"), "</svg>"])


def lockup(stacked=False):
    """Mark + wordmark. Mark cap height is tuned against the x-height."""
    mh = 364.0                               # tuned so the die wall matches the wordmark weight
    scale = mh / (MARK_HALF * 2)
    wm_h = WORD_BOT - WORD_TOP
    ws = 1.0
    if not stacked:
        gap = 84.0
        w = mh + gap + WORD_W
        h = max(mh, wm_h)
        mx, my = 0.0, (h - mh) / 2.0
        wx, wy = mh + gap, (h - wm_h) / 2.0 - WORD_TOP
    else:
        gap = 64.0
        ws = 0.66
        ww = WORD_W * ws
        w = max(mh, ww)
        h = mh + gap + wm_h * ws
        mx, my = (w - mh) / 2.0, 0.0
        wx, wy = (w - ww) / 2.0, mh + gap - WORD_TOP * ws
    return "\n".join([
        HDR.format(vb=f"0 0 {w:.1f} {h:.1f}", w=f"{w:.1f}", h=f"{h:.1f}", label="macop"),
        f'''  <defs>
    <linearGradient id="amber" x1="0" y1="{my+mh*0.34}" x2="0" y2="{my+mh*0.72}" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="{AMBER[0][1]}"/><stop offset="1" stop-color="{AMBER[1][1]}"/>
    </linearGradient>
  </defs>''',
        f'  <g transform="translate({mx+mh/2:.1f} {my+mh/2:.1f}) scale({scale:.5f})">',
        mark_group(4, "currentColor", "url(#amber)"), "  </g>",
        f'  <g transform="translate({wx:.1f} {wy:.1f}) scale({ws:.4f})">',
        wordmark_group(4, "currentColor"), "  </g>", "</svg>"])


def write(name, text):
    p = os.path.join(OUT, name)
    with open(p, "w") as f:
        f.write(text + "\n")
    print("  svg/" + name)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    print("macop logo ->")
    write("macop-icon.svg", app_icon())
    write("macop-mark.svg", mark_svg(color=True))
    write("macop-mark-mono.svg", mark_svg(color=False))
    write("macop-wordmark.svg", wordmark_svg())
    write("macop-lockup.svg", lockup(False))
    write("macop-lockup-stacked.svg", lockup(True))
