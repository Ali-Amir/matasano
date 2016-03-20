-- @module lib.attacks.common

local bytes = require('lib.bytes')
local sorting = require('lib.sorting')
local toolbox = require('lib.toolbox')

local common = {}

function common.break_one_char_encryption(seq)
  --[[ Given a byte sequence that is a result of a single character encryption
  -- of plaintext English, returns a list of potential candidate decodings in
  -- the decreasing order of likelihood.
  --
  -- seq: Array of bytes, the ciphertext.
  -- return:
  -- - An array of pairs ((k, v), score), where k is the key, v is the decryption
  --   as a plaintext and score is the likelihood. The array is sorted by
  --   decreasing likelihood.
  --]]
  local scores = {}
  for i = 0, 255 do
    local b = {}
    for j = 1,#seq do
      table.insert(b, i)
    end
    local c = bytes.bytearrayxor(seq, b)
    local text = bytes.bytearray2string(c)
    local cur_score = toolbox.score_string_as_english(text)
    local index = {}
    index[1] = i
    index[2] = text
    scores[index] = cur_score
  end

  local kv_pairs = sorting.sort_table_by_value(scores)
  return kv_pairs
end

function common.break_k_char_encoding(seq, key_size)
  --[[ Given a byte sequence that is a result of a key_size character encryption
  -- of plaintext English, returns a list of potential candidate decodings in
  -- the decreasing order of likelihood.
  --
  -- seq: Array of bytes, the ciphertext.
  -- return:
  -- - An array of pairs ((k, v), score), where k is the key, v is the decryption
  --   as a plaintext and score is the likelihood. The array is sorted by
  --   decreasing likelihood.
  --]]
  local transposed = {}
  for i = 1,key_size do
    transposed[i] = {}
  end
  for i = 1,#seq do
    table.insert(transposed[(i - 1) % key_size + 1], seq[i])
  end

  local guesses = {}
  for i = 1,key_size do
    guesses[i] = common.break_one_char_encryption(transposed[i])
  end

  local kv_pairs = {}
  for ind = 1,256 do
    -- Assemble the key and get average score.
    local cur_key = {}
    local cur_score = 0.0
    for i = 1,key_size do
      table.insert(cur_key, guesses[i][ind][1][1])
      cur_score = cur_score + guesses[i][ind][2]/key_size
    end
    -- Assemble the candidate plaintext.
    local plaintext = ""
    for l = 1,#transposed[1] do
      for i = 1,key_size do
        if l <= #transposed[i] then
          plaintext = plaintext .. guesses[i][ind][1][2]:sub(l,l)
        end
      end
    end
    local index = {}
    index[1] = cur_key
    index[2] = plaintext
    kv_pairs[#kv_pairs + 1] = {index, cur_score}
  end
  return kv_pairs
end

return common
