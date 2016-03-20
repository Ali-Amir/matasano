-- @module lib.modes.ecb

local ecb = {}

function ecb.encrypt(plaintext, key, block_cipher)
  --[[ Encrypts a plaintext under ECB mode:
  -- https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
  --
  -- plaintext: Array of bytes, representing the text to be encrypted.
  -- block_cipher: A function that accepts a block of 128-bytes and returns a
  --               ciphertext.
  -- return:
  -- - Array of bytes, the ciphertext
  --]]

  -- Make a copy padded with 100...00
  local seq = {}
  for i = 1,#plaintext do
    table.insert(seq, plaintext[i])
  end
  table.insert(seq, 128)
  while #seq % 16 ~= 0 do
    table.insert(seq, 0)
  end

  local ciphertext = {}
  for i = 1,#seq,16 do
    local block = {}
    for j = 0,15 do
      table.insert(block, seq[i+j])
    end

    local cipherblock = block_cipher.encrypt(block, key)
    for j = 1,#cipherblock do
      table.insert(ciphertext, cipherblock[j])
    end
  end
  return ciphertext
end

function ecb.decrypt(ciphertext, key, block_cipher)

end

return ecb
