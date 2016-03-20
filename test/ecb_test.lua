local aes = require('lib.block_ciphers.aes')
local ecb = require('lib.modes.ecb')
local bytes = require('lib.bytes')

--- TEST end to end ---
print("Testing end to end:")
key = bytes.string2bytearray('YELLOW SUBMARINE')
plaintext = bytes.string2bytearray('TOGETHER BECAUSETOGETHER BECAUSE')
ciphertext = bytes.bytearray2hex(ecb.encrypt(plaintext, key, aes))
print("Encrypt: " .. ciphertext)
assert(ciphertext:sub(1,64) == "58ee3bdb274c35d5fb3c8a64ba67b2ca58ee3bdb274c35d5fb3c8a64ba67b2ca",
       "Wrong answer!")

plaintext_decrypt = ecb.decrypt(bytes.hex2bytearray(ciphertext), key, aes)
print("Decrypt: " .. bytes.bytearray2string(plaintext_decrypt))
assert(bytes.bytearray2string(plaintext_decrypt) == bytes.bytearray2string(plaintext),
      "Expected " .. bytes.bytearray2string(plaintext) .. " but got " ..
      bytes.bytearray2string(plaintext_decrypt))
