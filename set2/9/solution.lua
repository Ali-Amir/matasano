local bytes = require('lib.bytes')
local padding = require('lib.padding.pkcs7')

msg = bytes.string2bytearray("YELLOW SUBMARINE")
print(bytes.bytearray2string(padding.pad(msg, 20)))
for i = 1,20 do
  print(padding.pad(msg,20)[i])
end
