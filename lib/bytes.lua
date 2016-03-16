-- lib/bytes.lua
module(..., package.seeall)

function hexdigit2decimal(a)
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

function decimal2hexdigit(a)
  --[[ Converts a decimal value into a hex digit.
  --
  -- a: Integer, with value in [0..256).
  -- return: Char, hex digit.
  --]]
  if a < 10 then
    return string.char(string.byte("0") + a)
  else
    return string.char(string.byte("a") + a - 10)
  end
end

function decimal2base64digit(a)
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

function hex2bytearray(a)
  --[[ Converts a hex string into a corresponding byte array.
  -- 
  -- a: String, hex.
  -- return:
  -- - Array of bytes.
  --]]
  result = {}
  for i = 1, string.len(a), 2 do
    first_triple = hexdigit2decimal(a:sub(i, i))
    second_triple = hexdigit2decimal(a:sub(i+1, i+1))
    byte = first_triple*16 + second_triple 
    table.insert(result, byte)
  end
  return result
end

function bytearray2base64(a)
  --[[ Converts a byte array into a base64 string.
  --
  -- a: Byte array.
  -- return:
  -- - Base64 string.
  --]]
  result = ""
  for i = 1, #a, 3 do
    a1 = a[i]
    a2 = a[i+1] or 0
    a3 = a[i+2] or 0
    total_value = a1*256*256 + a2*256 + a3

    c1 = decimal2base64digit(math.floor(total_value / math.pow(64, 3)))
    c2 = decimal2base64digit(math.floor((total_value / math.pow(64, 2))) % 64)
    c3 = decimal2base64digit(math.floor((total_value / math.pow(64, 1))) % 64)
    c4 = decimal2base64digit(total_value % 64)

    if i == #a then
      c3, c4 = "=", "="      
    elseif i + 1 == #a then
      c4 = "=" 
    end
    result = result .. c1 .. c2 .. c3 ..c4
  end
  return result
end

function bytearrayxor(a, b)
  --[[ Computes elementwise xor of two byte arrays.
  --
  -- a, b: Byte arrays to be xored; have to be of the same length.
  -- return:
  -- - Byte array of the same length as input arrays.
  --]]
  c = {}
  for i = 1, #a do
    table.insert(c, bit32.bxor(a[i], b[i]))
  end
  return c
end

function bytearray2hex(a)
  --[[ Computes a hex representation of a byte array.
  --
  -- a: Byte array.
  -- return:
  -- - Hex string.
  --]]
  c = ""
  for i = 1, #a do
    byte = a[i]
    c1 = decimal2hexdigit(math.floor(byte / 16))
    c2 = decimal2hexdigit(byte % 16)
    c = c .. c1 .. c2
  end
  return c
end
