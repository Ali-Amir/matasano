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
  -- - Array of bytes, the ciphertext.
  --]]

  -- Make a copy padded with zeros. --100...00
  local seq = {}
  for i = 1,#plaintext do
    table.insert(seq, plaintext[i])
  end
  --table.insert(seq, 128) -- Using zero padding.
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
  --[[ Decrypts a ciphertext under ECB mode:
  -- https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
  --
  -- ciphertext: Array of bytes, representing the text to be decrypted.
  -- block_cipher: A function that accepts a ciphertext, key of 128-bytes and
  --               returns a plaintext.
  -- return:
  -- - Array of bytes, the plaintext. 
  --]]
  
  assert(#ciphertext % 16 == 0, "Ciphertext length has to be divisible by 16! "
         .. #ciphertext)

  local plaintext_padded = {}
  for i = 1,#ciphertext,16 do
    local block = {}
    for j = 0,15 do
      table.insert(block, ciphertext[i+j])
    end

    local cipherblock = block_cipher.decrypt(block, key)
    for j = 1,#cipherblock do
      table.insert(plaintext_padded, cipherblock[j])
    end
  end

  -- In case no padding was added, returned the whole thing.
  --pad_pos = #plaintext_padded + 1
  pad_pos = #plaintext_padded + 1
  for i = 1,#plaintext_padded do
    --if plaintext_padded[i] == 128 then
    if plaintext_padded[i] ~= 0 then
      pad_pos = i + 1
    end
  end

  plaintext = {}
  for i = 1,pad_pos - 1 do
    table.insert(plaintext, plaintext_padded[i])
  end
  return plaintext
end

return ecb
