local aes = require('lib.block_ciphers.aes')
local bytes = require('lib.bytes')

key = bytes.string2bytearray('YELLOW SUBMARINE')
plaintext = bytes.string2bytearray('TOGETHER BECAUSE')

print(bytes.bytearray2hex(aes.encrypt(plaintext, key)))
