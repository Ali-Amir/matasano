local bytes = require('lib.bytes')
local toolbox = require('lib.toolbox')

oracle = toolbox.new_encryption_oracle_aes_ecb()
print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))
print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))
print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))
print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))

