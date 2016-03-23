-- @module lib.attacks.detection

local bytes = require('lib.bytes')
local toolbox = require('lib.toolbox')

local detection = {}

function detection.detect_ecb(oracle, block_size)
  --[[ Detects whether the encryption oracle encrypts with ECB.
  -- 
  -- oracle: Function, encryption oracle.
  -- block_size: Integer, block size; defaults to 16 bytes/128 bits.
  -- return:
  -- - Boolean, true iff oracle encrypted with ECB and false otherwise.
  --]]
  block_size = block_size or 16

  encrypted = bytes.bytearray2string(
    oracle(
      toolbox.replicate_to_match(
        {string.byte('A')},
        block_size*3)))

  counts = {}
  for i = 1,#encrypted,block_size do
    substr = encrypted:sub(i, i+block_size-1)
    if counts[substr] == nil then
      counts[substr] = 1
    else
      return true
    end
  end
  return false
end

return detection
