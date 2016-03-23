local bytes = require('lib.bytes')
local pkcs7 = require('lib.padding.pkcs7')

--- Test valid ---
valid = "ICE ICE BABY\x04\x04\x04\x04"
print("Testing valid string...")
assert(bytes.bytearray2string(pkcs7.unpad(bytes.string2bytearray(valid))) ==
       "ICE ICE BABY", "Wrong answer")
print("OK!")

--- Test invalid 1 ---
invalid1 = "ICE ICE BABY\x05\x05\x05\x05"
print("Testing invalid string 1...")
assert(not pcall(function() pkcs7.unpad(bytes.string2bytearray(invalid1)) end))
print("OK!")

--- Test invalid 2 ---
invalid2 = "ICE ICE BABY\x01\x02\x03\x04"
print("Testing invalid string 2...")
assert(not pcall(function() pkcs7.unpad(bytes.string2bytearray(invalid2)) end))
print("OK!")
