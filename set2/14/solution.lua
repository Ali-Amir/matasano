local bytes = require('lib.bytes')
local detection = require('lib.attacks.detection')
local english = require('lib.english')
local toolbox = require('lib.toolbox')

function figure_out_block_size(oracle)
  --[[ Given an oracle, determines the block size it is using for encryption.
  --
  -- oracle: Function, encryption oracle.
  -- return:
  -- - Integer, block size.
  --]]
  local gcd = 0
  for i = 1,60 do
    gcd = toolbox.gcd(gcd, #oracle(toolbox.replicate_to_match({string.byte('A')}, i)))
  end
  return gcd
end

function figure_out_enc_pattern(oracle, ipattern)
  --[[ Figures out what ipattern encrypts to under the given oracle, which
  -- operates in ECB mode.
  --
  -- oracle: Function, encryption oracle.
  -- ipattern: Array of bytes, of length block_size of the oracle.
  -- return:
  -- - Array of bytes, the encryption of ipattern.
  --]]
  local block_size = #ipattern
  local attack = string.rep(bytes.bytearray2string(ipattern), 4)
  local required_count = 3
  while true do
    local enc = bytes.bytearray2string(oracle(bytes.string2bytearray(attack)))
    local current_count = 0
    for i = 1,#enc-block_size,block_size do
      if enc:sub(i, i+block_size-1) == enc:sub(i+block_size, i+2*block_size-1) then
        current_count = current_count + 1
      end
    end
    if (current_count >= required_count) then
      for i = 1,#enc-2*block_size+1,block_size do
        if enc:sub(i, i+block_size-1) == enc:sub(i+block_size, i+2*block_size-1) then
          print("Starting enc pattern from: " .. i)
          return bytes.string2bytearray(enc:sub(i, i+block_size-1))
        end
      end
    end
  end
end

function encrypt_until_match_occurs(oracle, input, pattern)
  --[[ Encrypts until oracle(input) contains pattern. Returns that
  -- oracle(input).
  --
  -- oracle: Function, encryption oracle.
  -- input: Byte array, input to the oracle.
  -- pattern: Byte array, pattern to match.
  -- return:
  -- - Byte array, corresponding oracle(input).
  --]]
  local pattern_str = bytes.bytearray2string(pattern)
  while true do
    local enc = bytes.bytearray2string(oracle(input))
    for pos = 1,#enc-#pattern+1,#pattern do
      if enc:sub(pos, pos+#pattern-1) == pattern_str then
        return bytes.string2bytearray(enc)
      end
    end
  end
end

enc_or, dec_or = toolbox.new_encryption_oracle_aes_ecb(bytes.string2bytearray("ALLOHA BROTHERS"),
                                                       {random_prepend = true,
                                                        prepend_range = {1,100}})
-- 1. Figure out block size.
local block_size = figure_out_block_size(enc_or)
-- 2. Detect whether it is using ECB.
local is_ecb = detection.detect_ecb(enc_or)
if not is_ecb then
  return
end
-- 3. Initialize variables.
local attack_length = block_size * 3
--local unknown_str_pad_len = figure_out_unknown_len(enc_or) TODO
local unknown_str_padded = ""
local identification_pattern = bytes.string2bytearray(string.rep('\x00', block_size))
local enc_pattern = figure_out_enc_pattern(enc_or, identification_pattern)
assert(#enc_pattern == block_size)
print("enc_pattern: " .. bytes.bytearray2hex(enc_pattern))
-- 4. Brute valid chars first.
-- Find out what \x0\x0\x0...\x0 encrypts to.
-- Attack with \x0\x0\x0...\x0 AAAAAo
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
-- 5. Recover unknown string byte by byte.
while true do
  -- Setup an attack string and its encryption.
  local num_a = ((-#unknown_str_padded - 1) % block_size + block_size) %
      block_size
  local attack_str = bytes.bytearray2string(identification_pattern) ..
                     string.rep('A', num_a)
  print("Attack_length " .. #attack_str)
  local attack_bytes = bytes.string2bytearray(attack_str)
  local enc = bytes.bytearray2string(encrypt_until_match_occurs(enc_or, attack_bytes, enc_pattern))
  -- Figure out where the AAAA... pattern starts.
  local start_pos = 1
  while enc:sub(start_pos, start_pos+block_size - 1) ~= bytes.bytearray2string(enc_pattern) do
    start_pos = start_pos + block_size
  end
  -- Figure out which block to consider. 
  local block_start_pos = start_pos + block_size +
      math.floor(#unknown_str_padded / block_size) * block_size
  local block = enc:sub(block_start_pos, block_start_pos + block_size - 1)
  for brute_ind = 1,256 do
    local brute_ch = brute_order[brute_ind]
    local try_str = attack_str .. unknown_str_padded .. string.char(brute_ch)
    assert(#try_str % block_size == 0)
    local try_bytes = bytes.string2bytearray(try_str)
    local try_enc = bytes.bytearray2string(encrypt_until_match_occurs(enc_or, try_bytes, enc_pattern))
    -- Find out where the pattern \x00 \x00 starts in the try string.
    local try_start_pos = 1
    while try_enc:sub(try_start_pos, try_start_pos+block_size - 1) ~= bytes.bytearray2string(enc_pattern) do
      try_start_pos = try_start_pos + block_size
    end
    -- Get the corresponding block.
    assert(#try_str - block_size == block_size +
      math.floor(#unknown_str_padded / block_size) * block_size)
    local try_block = try_enc:sub(try_start_pos + #try_str - block_size,
                                  try_start_pos + #try_str - 1)
    if try_block == block then
      print("Found a char " .. brute_ch .. " " .. string.char(brute_ch))
      unknown_str_padded = unknown_str_padded .. string.char(brute_ch)
      break
    end
  end
end
