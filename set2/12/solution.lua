local bytes = require('lib.bytes')
local detection = require('lib.attacks.detection')
local english = require('lib.english')
local pkcs7 = require('lib.padding.pkcs7')
local toolbox = require('lib.toolbox')

oracle = toolbox.new_encryption_oracle_aes_ecb()

function figure_out_block_size(oracle)
  --[[ Given an oracle, determines the block size it is using for encryption.
  --
  -- oracle: Function, encryption oracle.
  -- return:
  -- - Integer, block size.
  --]]
  gcd = 0
  for i = 1,32 do
    gcd = toolbox.gcd(gcd, #oracle(toolbox.replicate_to_match({string.byte('A')}, i)))
  end
  return gcd
end

-- 1. Figure out block size.
local block_size = figure_out_block_size(oracle)
-- 2. Detect whether it is using ECB.
local is_ecb = detection.detect_ecb(oracle)
-- 3. Recover unknown string byte by byte.
local unknown_len = #oracle({})
local num_blocks_to_match = math.floor((unknown_len + block_size - 1)/block_size)
local block_multiple = num_blocks_to_match * block_size
local unknown_str_padded = ""
-- 3.a Brute valid chars first.
local brute_order = {}
for i = 0,255 do
  if english.is_valid_char(string.char(i)) then
    table.insert(brute_order, i)
  end
end
for i = 0,255 do
  if not english.is_valid_char(string.char(i)) then
    table.insert(brute_order, i)
  end
end

for i = 1,unknown_len do
  local feed_pref = bytes.bytearray2string(
      toolbox.replicate_to_match({string.byte('A')}, block_multiple - i))
  local enc_block = bytes.bytearray2string(
    oracle(bytes.string2bytearray(feed_pref))):sub(
      (num_blocks_to_match - 1)*block_size + 1, num_blocks_to_match*block_size)
  for brute_ind = 1,256 do
    local ch = brute_order[brute_ind]
    local feed = feed_pref .. unknown_str_padded .. string.char(ch)
    local block = bytes.bytearray2string(oracle(bytes.string2bytearray(feed))):sub((num_blocks_to_match - 1)*block_size + 1,
        num_blocks_to_match*block_size)
    if block == enc_block then
      unknown_str_padded = unknown_str_padded .. string.char(ch)
      print("Adding: " .. ch .. ". Current string: " .. unknown_str_padded)
      break
    end
  end
end
unknown_str = bytes.bytearray2string(pkcs7.unpad(bytes.string2bytearray(unknown_str_padded)))

print("Block size = " .. block_size)
print("Is ECB = " .. tostring(is_ecb))
print("Detected string = " .. unknown_str)
print("Checking correctness...")

local append_text = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
assert(unknown_str == bytes.bytearray2string(bytes.base642bytearray(append_text)))

print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))
print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))
print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))
print(bytes.bytearray2hex(oracle(bytes.string2bytearray("YELLOW SUBMARINE"))))
