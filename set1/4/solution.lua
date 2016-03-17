local bytes = require('lib.bytes')
local toolbox = require('lib.toolbox')

best_so_far = math.huge
best_decoding = ""

io.input("set1/4/4.txt")
while true do
  local cipher = io.read()
  if cipher == nil then break end

  cipher_bytes = bytes.hex2bytearray(cipher)
  decodings = toolbox.decode_one_char_encryption(cipher_bytes)
  if decodings[1][2] < best_so_far then
    best_so_far = decodings[1][2]
    best_decoding = decodings[1][1][2]
  end
end

print(best_decoding)
