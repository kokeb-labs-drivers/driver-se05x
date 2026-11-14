"""The SE052 HVQFN20 pin table, from SE052 data sheet Rev. 1.5, Table 2 Pin description for SE052 (p. 4), with the
supplies of Table 13 (p. 18) and the integration of Figure 1 (p. 6). docs/hardware.yml describes the HX2QFN20 of the
SE050 and SE051 only (one package per file), so the SE052 figures read this table.
"""

REF = "SE052 data sheet Rev. 1.5, Table 2, p. 4"

# (number, name, type, function); the type names are those of docs/hardware.yml.
PINS = [
    (1, "LB", "analog", "antenna coil connection; not used by this driver"),
    (2, "n.c.", "nc", "not connected"),
    (3, "IO1", "digital-io", "SDA of the chip's I2C controller (or ISO 7816 GPIO)"),
    (4, "n.c.", "nc", "not connected"),
    (5, "n.c.", "nc", "not connected"),
    (6, "n.c.", "nc", "not connected"),
    (7, "n.c.", "nc", "not connected"),
    (8, "n.c.", "nc", "not connected"),
    (9, "n.c.", "nc", "not connected"),
    (10, "SCL", "bus", "I2C clock"),
    (11, "SDA", "bus", "I2C data"),
    (12, "VIN", "power", "supply of SCL, SDA and IO2, logic supply for I2C; 1.65 V to 3.6 V"),
    (13, "CLK", "digital-in", "not connected (or ISO 7816 clock)"),
    (14, "RST_N", "digital-in", "low triggers a device reset; at least 40 us (Table 14, p. 20)"),
    (15, "VOUT", "power-out", "supply output, connect to VDD on the board"),
    (16, "IO2", "digital-io", "SCL of the chip's I2C controller (or ISO 7816 GPIO2)"),
    (17, "LA", "analog", "antenna coil connection; not used by this driver"),
    (18, "VDD", "power", "supply input; 1.62 V to 5.5 V by class (Table 13, p. 18)"),
    (19, "VSS", "ground", "ground"),
    (20, "n.c.", "nc", "not connected"),
]

TONES = {"power": "rose", "ground": "slate", "bus": "blue", "digital-in": "teal", "digital-io": "violet",
         "analog": "magenta", "power-out": "brown", "nc": "stone"}
