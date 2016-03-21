local aes = require('lib.block_ciphers.aes')
local bytes = require('lib.bytes')
local cbc = require('lib.modes.cbc')
local ecb = require('lib.modes.ecb')

function encryption_oracle(data_org)
  --[[ An encryption oracle that encrypts given data under either AES-ECB or
  -- AES-CBC.
  --
  -- The function generates a random 16-byte AES key and encrypts in either ECB
  -- or CBC modes equally likely.
  --
  -- data_org: Array of bytes, original data; not modified.
  -- return:
  -- - Array of bytes, the encrypted text.
  --]]
  -- Append a random number of bytes in the front and back.
  math.randomseed(os.time())
  num_bytes_front = math.random(5, 10)
  data = bytes.random_bytearray(num_bytes_front)
  for i = 1,#data_org do
    table.insert(data, data_org[i])
  end
  num_bytes_back = math.random(5, 10)
  for i = 1,num_bytes_back do
    table.insert(data, math.random(256) - 1)
  end
  -- Generate the key one byte at a time.
  key = bytes.random_bytearray(16)
  -- Make a decision on the mode of encryption.
  mode = math.random(2)
  if mode == 1 then
    print("CBC")
    IV = bytes.random_bytearray(16)
    return cbc.encrypt(data, key, aes, {IV = IV})
  elseif mode == 2 then
    print("ECB")
    return ecb.encrypt(data, key, aes)
  else
    assert(false, "Something is wrong!")
  end
end

print(bytes.bytearray2hex(encryption_oracle("HELLO")))
