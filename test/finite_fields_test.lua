local GF256 = require('lib.finite_fields').GF256

assert(GF256:new(0x95):mul(GF256:new(0x8A)).v == 1, "Wrong answer!")
