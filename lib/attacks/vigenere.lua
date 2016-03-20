-- @module lib.attacks.vigenere

local bytes = require('lib.bytes')
local common = require('lib.attacks.common')
local sorting = require('lib.sorting')
local toolbox = require('lib.toolbox')

local vigenere = {}

function vigenere.score_key_size(seq, key_size, num_blocks)
  --[[ Computes a score that reflects a likelihood of seq being encrypted with
  -- key of size key_size. Lower score corresponds to lower likelihood.
  --
  -- In order to compute the score takes the first num_blocks of size key_size
  -- and computes pairwise hamming distances of corresponding characters in the
  -- blocks: first character in first block with first character in second ...,
  -- second character in first with second character in second ... and so on.
  -- The score is the average pairwise hamming distance.
  --
  -- seq: Array of bytes, the encoded sequence.
  -- key_size: Integer, target key size to be checked.
  -- num_blocks: Integer, number of first blocks to be checked; defaults to 3.
  --]]
  num_blocks = num_blocks or 3

  local limit = math.min(num_blocks * key_size - 1, #seq)

  local total_sum_hd = 0.0
  local num_summands = 0
  for f_element = 1,limit,key_size do
    for s_element = f_element+key_size,limit,key_size do
      local f_array = {}
      local s_array = {}
      for i = 1,key_size do
        table.insert(f_array, seq[f_element + i - 1])
        if s_element+i-1 <= limit then
          table.insert(s_array, seq[s_element + i - 1])
        else
          table.insert(s_array, 0)
        end
      end
      total_sum_hd = total_sum_hd + toolbox.hamming_distance(f_array, s_array)/key_size
      num_summands = num_summands + 1
    end
  end
  return total_sum_hd / num_summands
end

function vigenere.attack(seq)
  --[[ Determines the most likely encryption key, as well as the plaintext given
  -- a ciphertext encoded with a repeated key.
  --
  -- seq: Array of bytes, plaintext encoded with Vigenere cipher.
  -- return:
  -- - An array of pairs ((k, v), score), where k is the key, v is the decryption
  --   as a plaintext and score is the likelihood. The array is sorted by
  --   decreasing likelihood. All of the keys have the same key size that was
  --   determined to be the most likely.
  --]]
  local key_score_map = {}
  for KEY_SIZE = 1,40 do
    key_score_map[KEY_SIZE] = vigenere.score_key_size(text_bytes, KEY_SIZE, 4)
  end
  local key_score_pairs = sorting.sort_table_by_value(key_score_map)
  local candidates = common.break_k_char_encoding(text_bytes, key_score_pairs[1][1])
  return candidates 
end

return vigenere
