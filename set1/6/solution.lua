local bytes = require('lib.bytes')
local files = require('lib.files')
local sorting = require('lib.sorting')
local toolbox = require('lib.toolbox')

-- Test 1 --
a = "this is a test"
b = "wokka wokka!!!"
print(toolbox.hamming_distance(bytes.string2bytearray(a),
                                bytes.string2bytearray(b)))
assert(toolbox.hamming_distance(bytes.string2bytearray(a),
                                bytes.string2bytearray(b)) == 37, "HD is wrong!")

-- Getting the input file
text = files.readfile("set1/6/6.txt"):gsub("\n", "")
text_bytes = bytes.base642bytearray(text)

candidates = toolbox.decode_vigenere(text_bytes)
print("Best result="..candidates[1][1][2])

