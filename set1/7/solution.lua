local block_ciphers = {}
function block_ciphers.AES(block, key)
  --[[ Encrypts a block of size 128 with a key key under AES:
  -- https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
  --
  -- block: Array of bytes, of length 128, the plaintext to be encrypted.
  -- key: Integer, key of encryption.
  -- return:
  -- - Array of bytes, the ciphertext.
  --]]
  -- TODO
end

local modes = {}
function modes.ECB(plaintext, key, block_cipher)
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
