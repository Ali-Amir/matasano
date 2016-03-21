local bytes = require('lib.bytes')
local padding = require('lib.padding.pkcs7')

msg = bytes.string2bytearray("YELLOW SUBMARINE")
padded = padding.pad(msg, 20)
print("Padded: " .. bytes.bytearray2string(padded))
print(bytes.bytearray2string(padded):sub(1,16))
assert(bytes.bytearray2string(msg) == bytes.bytearray2string(padded):sub(1,16),
       "Wrong answer!")
assert("\x04\x04\x04\x04" == bytes.bytearray2string(padded):sub(17,20),
       "Wrong answer!")
assert(bytes.bytearray2string(padding.unpad(padded)) == bytes.bytearray2string(msg),
       "Wrong answer!")
