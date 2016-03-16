local toolbox = require('lib.toolbox')
local bytes = require('lib.bytes')

-- Test 1 --
a = "this is a test"
b = "wokka wokka!!!"
print(toolbox.hamming_distance(bytes.string2bytearray(a),
                                bytes.string2bytearray(b)))
assert(toolbox.hamming_distance(bytes.string2bytearray(a),
                                bytes.string2bytearray(b)) == 37, "HD is wrong!")
