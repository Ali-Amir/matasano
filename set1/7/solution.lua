local aes = require('lib.block_ciphers.aes')
local bytes = require('lib.bytes')
local ecb = require('lib.modes.ecb')
local files = require('lib.files')

ciphertext = files.readfile("set1/7/7.txt"):gsub("\n", "")
ciphertext_bytes = bytes.base642bytearray(ciphertext)
key_bytes = bytes.string2bytearray("YELLOW SUBMARINE")

print("ciphertext_bytes length: " .. #ciphertext_bytes)
text_bytes = ecb.decrypt(ciphertext_bytes, key_bytes, aes)
print("Decoded:\n" .. bytes.bytearray2string(text_bytes))
