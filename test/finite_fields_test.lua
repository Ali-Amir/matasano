local GF256 = require('lib.finite_fields').GF256

assert(GF256:new(0x95):mul(GF256:new(0x8A)).v == 1, "Wrong answer!")
assert(GF256:new(0x0):mul(GF256:new(0x8A)).v == 0, "Wrong answer!")
assert(GF256:new(0x0):mul(GF256:new(0x0)).v == 0, "Wrong answer!")

