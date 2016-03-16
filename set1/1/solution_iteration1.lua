function hex2decimal(a)
  --[[ Converts a hex digit into its decimal value.
  --
  -- a: Char, a hex digit.
  -- return: Integer, its decimal value.
  --]]
  if a >= "a" and a <= "z" then
    return string.byte(a) - string.byte("a") + 10
  end
  return string.byte(a) - string.byte("0")
end

function decimal2base64(a)
  --[[ Converts a decimal into a single base64 digit.
  --
  -- a: Integer, with value in [0..64).
  -- return: Char, base64 digit.
  --]]
  if a < 26 then
    return string.char(string.byte("A") + a)
  elseif a < 52 then
    return string.char(string.byte("a") + a - 26)
  elseif a < 62 then
    return string.char(string.byte("0") + a - 52)
  elseif a == 62 then
    return "+"
  else
    return "/"
  end
end

function hexblock2base64(a,b,c)
  --[[ Converts a 3 digit block of hex into two digits of base64.
  --
  -- a,b,c: Char, are hex digits with a being the highest.
  -- return:
  -- - Char,  base64 higher digit.
  -- - Char, base64 lower digit.
  --]]
  total_value = hex2decimal(a)*16*16 + hex2decimal(b)*16 + hex2decimal(c)
  return decimal2base64(math.floor(total_value / 64)), decimal2base64(total_value % 64)
end

function hex2base64(s)
  --[[ Converts a hex string into base64 string.
  --
  -- s: String, representation of the hex.
  -- return:
  -- - String, base64 representation of the input.
  --]]
  res_inv = ""
  while s:len() % 3 ~= 0 do
    s = "0" .. s
    res_inv = res_inv .. "="
  end
  for i = string.len(s)-2, 1, -3 do
    local c1 = string.sub(s, i, i) or "0"
    local c2 = string.sub(s, i+1, i+1) or "0"
    local c3 = string.sub(s, i+2, i+2) or "0"
    d1, d2 = hexblock2base64(c1, c2, c3)
    res_inv = res_inv .. d2 .. d1
  end
  while res_inv:len() > 1 and res_inv:sub(-1,-1)=="A" do
    res_inv = res_inv:sub(1,res_inv:len() - 1)
  end
  return string.reverse(res_inv)
end

print(hex2base64("a"))
print(hex2base64("0"))
print(hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
