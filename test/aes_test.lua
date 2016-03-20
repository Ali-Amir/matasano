local aes = require('lib.block_ciphers.aes')
local bytes = require('lib.bytes')

--- TEST AESMat add ---
print("Testing matmul:")
block1 = {}
block2 = {}
for i = 0,15 do
  block1[i+1] = i
  block2[i+1] = 15-i
end
mat1 = aes.AESMat:new(block1)
mat2 = aes.AESMat:new(block2)
addmats = mat1:add(mat2)
for i = 1,4 do
  out = ""
  for j = 1,4 do
    assert(addmats.a[i][j] == 15, "Wrong answer!")
    out = out .. addmats.a[i][j] .. " "
  end
  print(out)
end
print()

-- TEST mix columns ---
print("Testing mix columns:")
mix_col_block = {0xd4, 0xbf, 0x5d, 0x30,
                 0xe0, 0xb4, 0x52, 0xae,
                 0xb8, 0x41, 0x11, 0xf1,
                 0x1e, 0x27, 0x98, 0xe5}
mix_col_mat = aes.AESMat:new(mix_col_block)
mix_col_mat:mix_columns()
expected_mixcol_block = {0x04, 0x66, 0x81, 0xe5,
                         0xe0, 0xcb, 0x19, 0x9a,
                         0x48, 0xf8, 0xd3, 0x7a,
                         0x28, 0x06, 0x26, 0x4c}
expected_mixcol_mat = aes.AESMat:new(expected_mixcol_block)
for i = 1,4 do
  out = ""
  for j = 1,4 do
    out = out .. bytes.bytearray2hex({mix_col_mat.a[i][j]}) .. " "
  end
  print(out)
end
print()
for i = 1,4 do
  for j = 1,4 do
    assert(mix_col_mat.a[i][j] == expected_mixcol_mat.a[i][j], "Wrong answer!")
  end
end

--- TEST shift rows ---
print("Testing shift rows:")
shift_block = {}
for i = 0,15 do
  table.insert(shift_block, math.floor(i/4))
end
shift_mat = aes.AESMat:new(shift_block)
shift_mat:shift_rows()
expected_shift_block = {0, 1, 2, 3,
                        1, 2, 3, 0,
                        2, 3, 0, 1,
                        3, 0, 1, 2}
expected_shift_mat = aes.AESMat:new(expected_shift_block)
for i = 1,4 do
  out = ""
  for j = 1,4 do
    out = out .. bytes.bytearray2hex({shift_mat.a[i][j]}) .. " "
  end
  print(out)
end
print()
for i = 1,4 do
  for j = 1,4 do
    assert(shift_mat.a[i][j] == expected_shift_mat.a[i][j], "Wrong answer!")
  end
end

--- TEST sub bytes ---
print("Testing sub bytes:")
sub_block = {0, 1, 2, 3,
             4, 5, 6, 7,
             8, 9, 10, 11,
             12, 13, 14, 15}
sub_mat = aes.AESMat:new(sub_block)
sub_mat:sub_bytes()
expected_sub_block = {0x63, 0x7c, 0x77, 0x7b,
                      0xf2, 0x6b, 0x6f, 0xc5,
                      0x30, 0x01, 0x67, 0x2b,
                      0xfe, 0xd7, 0xab, 0x76}
expected_sub_mat = aes.AESMat:new(expected_sub_block)
for i = 1,4 do
  out = ""
  for j = 1,4 do
    out = out .. bytes.bytearray2hex({sub_mat.a[i][j]}) .. " "
  end
  print(out)
end
print()
for i = 1,4 do
  for j = 1,4 do
    assert(sub_mat.a[i][j] == expected_sub_mat.a[i][j], "Wrong answer!")
  end
end

--- TEST key scheduler ---
print("Testing key scheduler:")
key = bytes.hex2bytearray("00000000000000000000000000000000")
scheduler = aes.KeyScheduler:new(aes.AESMat:new(key))
expected_keys = {"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ",
                 "62 63 63 63 62 63 63 63 62 63 63 63 62 63 63 63 ",
                 "9b 98 98 c9 f9 fb fb aa 9b 98 98 c9 f9 fb fb aa ",
                 "90 97 34 50 69 6c cf fa f2 f4 57 33 0b 0f ac 99 ",
                 "ee 06 da 7b 87 6a 15 81 75 9e 42 b2 7e 91 ee 2b ",
                 "7f 2e 2b 88 f8 44 3e 09 8d da 7c bb f3 4b 92 90 ",
                 "ec 61 4b 85 14 25 75 8c 99 ff 09 37 6a b4 9b a7 ",
                 "21 75 17 87 35 50 62 0b ac af 6b 3c c6 1b f0 9b ",
                 "0e f9 03 33 3b a9 61 38 97 06 0a 04 51 1d fa 9f ",
                 "b1 d4 d8 e2 8a 7d b9 da 1d 7b b3 de 4c 66 49 41 ",
                 "b4 ef 5b cb 3e 92 e2 11 23 e9 51 cf 6f 8f 18 8e "}

for r = 0,10 do
  round_key = scheduler:get_key(r)
  print("== Round " .. r .. " key is:")
  str_key = ""
  for j = 1,4 do
    for i = 1,4 do
      str_key = str_key .. bytes.bytearray2hex({round_key.a[i][j]}) .. " "
    end
  end
  print(str_key)
  print(expected_keys[r + 1])
  assert(str_key == expected_keys[r + 1], "Wrong answer for round " .. r)
end
print()

--- TEST end to end ---
print("Testing end to end:")
key = bytes.string2bytearray('YELLOW SUBMARINE')
plaintext = bytes.string2bytearray('TOGETHER BECAUSE')

print(bytes.bytearray2hex(aes.encrypt(plaintext, key)))
assert(bytes.bytearray2hex(aes.encrypt(plaintext, key)) == "58ee3bdb274c35d5fb3c8a64ba67b2ca", "Wrong answer!")
