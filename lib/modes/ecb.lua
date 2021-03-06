-- @module lib.modes.ecb

local ecb = {}

function ecb.encrypt(plaintext, key, block_cipher, extra_args)
  --[[ Encrypts a plaintext under ECB mode:
  -- https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
  --
  -- plaintext: Array of bytes, representing the text to be encrypted.
  -- block_cipher: A function that accepts a block of 128-bits and returns a
  --               ciphertext.
  -- extra_args: Map, additional arguments. Defaults to {}. Supports:
  --             - padding: Function, padding function to use. Defaults to
  --               lib/padding/pkcs7.
  --             - IV: Array of bytes, of length 16, the initialization vector
  --               to use.
  -- return:
  -- - Array of bytes, the ciphertext.
  --]]
  extra_args = extra_args or {}
  local padding = extra_args.padding or require('lib.padding.pkcs7')

  -- Pad the plaintext.
  local seq = padding.pad(plaintext, 16)
  local ciphertext = {}
  -- Run the block cipher on blocks.
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

function ecb.decrypt(ciphertext, key, block_cipher, padding)
  --[[ Decrypts a ciphertext under ECB mode:
  -- https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
  --
  -- ciphertext: Array of bytes, representing the text to be decrypted.
  -- block_cipher: A function that accepts a ciphertext, key of 128-bits and
  --               returns a plaintext.
  -- padding: Function, padding to use. Defaults to lib/padding/pkcs7.
  -- return:
  -- - Array of bytes, the plaintext. 
  --]]
  
  padding = padding or require('lib.padding.pkcs7')
  
  assert(#ciphertext % 16 == 0, "Ciphertext length has to be divisible by 16! "
         .. #ciphertext)

  local plaintext_padded = {}
  for i = 1,#ciphertext,16 do
    local block = {}
    for j = 0,15 do
      table.insert(block, ciphertext[i+j])
    end

    local plaintextblock = block_cipher.decrypt(block, key)
    for j = 1,#plaintextblock do
      table.insert(plaintext_padded, plaintextblock[j])
    end
  end

  local plaintext = padding.unpad(plaintext_padded)
  return plaintext
end

return ecb
