local bytes = require('lib.bytes')
local toolbox = require('lib.toolbox')

oracle = toolbox.new_encryption_oracle_aes_ecb()

function figure_out_block_size(oracle)
  --[[ Given an oracle, determines the block size it is using for encryption.
  --
  -- oracle: Function, encryption oracle using ECB.
  -- return:
  -- - Integer, block size.
  --]]
  gcd = 0
  for i = 1,32 do
    gcd = toolbox.gcd(gcd, #oracle(toolbox.replicate_to_match({string.byte('A')}, i)))
  end
  return gcd
end

print("Block size = " .. figure_out_block_size(oracle))
print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))
print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))
print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))
print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))

