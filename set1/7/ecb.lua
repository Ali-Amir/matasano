-- @module lib.modes.ecb

local ecb = {}

function ecb.encode(plaintext, key, block_cipher)
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
  seq = {}
  for i = 1,#plaintext do
    table.insert(seq, plaintext[i])
  end
  table.insert(seq, 1)
  while #seq % 128 ~= 0 do
    table.insert(seq, 0)
  end

  ciphertext = {}
  for i = 1,#seq,128 do
    block = {}
    for j = 0,127 do
      table.insert(block, seq[i+j])
    end

    cipherblock = block_cipher(block, key)
    for j = 1,#cipherblock do
      table.insert(ciphertext, cipherblock[j])
    end
  end
  return ciphertext
end

function ecb.decode()

end

return ecb
