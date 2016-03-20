-- @module lib.finite_fields

local finite_fields = {}

local GF256 = {}

function GF256:new(value)
  --[[ Creates a new element in GF(2^8) initialized to value.
  --
  -- value: Integer, between [0..256).
  -- return:
  -- - GF256 object, representation in GF(2^8).
  --]]
  local el = {}
  el.v = value
  setmetatable(GF256, {__index = el})
  return el
end

function GF256:mult(B)
  --[[ Multiplies self by B, as described in:
  -- https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael.27s_finite_field
  --
  -- B: GF256 object, multiplicand.
  -- return:
  -- - GF256 object, self after being multipled by b; modifies self.
  --]]
  a = self.v
  b = B.v
  local p = 0
  for iter = 1,8 do
    if a == 0 or b == 0 then
      break
    end

    if (b & 1) > 0 then
      p = p ~ a
    end

    -- Divide b by x.
    b = b >> 1
    -- Remember carry.
    carry = (a >> 7) & 1
    -- Multiply a by x.
    a = (a << 1) & 255
    if carry > 0 then
      a = a ~ 0x1b
    end
  end
  return GF256:new(p)
end

finite_fields.GF256 = GF256

return finite_fields
