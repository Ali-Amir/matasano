-- @module lib.bytes

local bytes = {}

function bytes.hexdigit2decimal(a)
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

function bytes.decimal2hexdigit(a)
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

function bytes.base64digit2decimal(a)
  --[[ Converts a base64 digit into its decimal value.
  --
  -- a: Char, a base64 digit.
  -- return: Integer, in range [0,64), value of the input.
  --]]
  if "A" <= a and a <= "Z" then
    return string.byte(a) - string.byte("A")
  elseif "a" <= a and a <= "z" then
    return string.byte(a) - string.byte("a") + 26
  elseif "0" <= a and a <= "9" then
    return string.byte(a) - string.byte("0") + 52
  elseif a == "+" then
    return 62
  else
    assert(a == "/" or a == "=", "Invalid character "..a)
    return 63
  end
end

function bytes.decimal2base64digit(a)
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

function bytes.hex2bytearray(a)
  --[[ Converts a hex string into a corresponding byte array.
  -- 
  -- a: String, hex.
  -- return:
  -- - Array of bytes.
  --]]
  local result = {}
  for i = 1, string.len(a), 2 do
    local first_triple = bytes.hexdigit2decimal(a:sub(i, i))
    local second_triple = bytes.hexdigit2decimal(a:sub(i+1, i+1))
    local byte = first_triple*16 + second_triple 
    table.insert(result, byte)
  end
  return result
end

function bytes.base642bytearray(a)
  --[[ Converts a base64 string into a corresponding byte array.
  -- 
  -- a: String, base64.
  -- return:
  -- - Array of bytes.
  --]]
  local result = {}
  for i = 1, string.len(a), 4 do
    local first_six = bytes.base64digit2decimal(a:sub(i, i))
    local second_six = bytes.base64digit2decimal(a:sub(i+1, i+1))
    local third_six = bytes.base64digit2decimal(a:sub(i+2, i+2))
    local fourth_six = bytes.base64digit2decimal(a:sub(i+3, i+3))
    local value = first_six*64*64*64 + second_six*64*64 + third_six*64 + fourth_six
    table.insert(result, math.floor(value / 256 / 256))
    if third_six ~= "=" then
      table.insert(result, math.floor(value / 256) % 256)
      if fourth_six ~= "=" then
        table.insert(result, value % 256)
      end
    end
  end
  return result
end

function bytes.bytearray2base64(a)
  --[[ Converts a byte array into a base64 string.
  --
  -- a: Byte array.
  -- return:
  -- - Base64 string.
  --]]
  local result = ""
  for i = 1, #a, 3 do
    local a1 = a[i]
    local a2 = a[i+1] or 0
    local a3 = a[i+2] or 0
    local total_value = a1*256*256 + a2*256 + a3

    local c1 = bytes.decimal2base64digit(math.floor(total_value / math.pow(64, 3)))
    local c2 = bytes.decimal2base64digit(math.floor((total_value / math.pow(64, 2))) % 64)
    local c3 = bytes.decimal2base64digit(math.floor((total_value / math.pow(64, 1))) % 64)
    local c4 = bytes.decimal2base64digit(total_value % 64)

    if i == #a then
      c3, c4 = "=", "="      
    elseif i + 1 == #a then
      c4 = "=" 
    end
    result = result .. c1 .. c2 .. c3 ..c4
  end
  return result
end

function bytes.bytearrayxor(a, b)
  --[[ Computes elementwise xor of two byte arrays.
  --
  -- a, b: Byte arrays to be xored; have to be of the same length.
  -- return:
  -- - Byte array of the same length as input arrays.
  --]]
  local c = {}
  for i = 1, #a do
    table.insert(c, bit32.bxor(a[i], b[i]))
  end
  return c
end

function bytes.bytearray2hex(a)
  --[[ Computes a hex representation of a byte array.
  --
  -- a: Byte array.
  -- return:
  -- - Hex string.
  --]]
  local c = ""
  for i = 1, #a do
    local byte = a[i]
    local c1 = bytes.decimal2hexdigit(math.floor(byte / 16))
    local c2 = bytes.decimal2hexdigit(byte % 16)
    c = c .. c1 .. c2
  end
  return c
end

function bytes.bytearray2string(a)
  --[[ Computes a string representation of a byte array.
  --
  -- a: Byte array.
  -- return:
  -- - String.
  --]]
  local c = ""
  for i = 1, #a do
    c = c .. string.char(a[i])
  end
  return c
end

function bytes.string2bytearray(a)
  --[[ Computes a byte array representation of a string.
  --
  -- a - String.
  -- return:
  -- - Byte array.
  --]]
  local byte_array = {}
  for i = 1, #a do
    table.insert(byte_array, string.byte(a:sub(i, i)))
  end
  return byte_array
end

function bytes.popcount(a)
  --[[ Computes number of 1's in the binary representation of a number.
  --
  -- a: Integer, number whose bits to count.
  -- return:
  -- - Integer, number of 1's.
  --]]
  local num_ones = 0
  local x = a
  while x > 0 do
    num_ones = num_ones + (bit32.band(x, 1))
    x = bit32.arshift(x, 1)
  end
  return num_ones
end

function bytes.random_bytearray(len)
  --[[ Generates a byte array with iid sampled bytes.
  --
  -- len: Integer, length of the target array.
  -- return:
  -- - Array of bytes, of length len with random content.
  --]]
  random_array = {}
  for i = 1,len do
    table.insert(random_array, math.random(256) - 1)
  end
  return random_array
end

return bytes
