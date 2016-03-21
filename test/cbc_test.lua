local aes = require('lib.block_ciphers.aes')
local bytes = require('lib.bytes')
local cbc = require('lib.modes.cbc')
local files = require('lib.files')

key = "YELLOW SUBMARINE"
key_bytes = bytes.string2bytearray(key)

ciphertext = files.readfile("set2/10/10.txt"):gsub("\n", "")
ciphertext_bytes = bytes.base642bytearray(ciphertext)

dec = cbc.decrypt(ciphertext_bytes, key_bytes, aes)
print("Decrypted:\n" .. bytes.bytearray2string(dec))
