-- @module lib.toolbox

local bytes = require('lib.bytes')
local english = require('lib.english')
local sorting = require('lib.sorting')
local vectors = require('lib.vectors')

local toolbox = {}

function toolbox.score_string_as_english(text)
  --[[ Returns a score for a given text. Higher score implies lower likelihood
  -- of the input text to be a valid English text.
  --
  -- text: String
  -- return:
  -- - Double, the score.
  --]]
  freq = {}
  for i = 1,#text do
    ch = string.lower(text:sub(i, i))
    if english.is_alpha(ch) then
      if freq[ch] == nil then
        freq[ch] = 0.0
      end
      freq[ch] = freq[ch] + 1.0 / #text
    end
  end

  penalty = 0.0
  for i = 1,#text do
    ch = text:sub(i, i)
    if not english.is_valid_char(ch) then
      penalty = penalty + 1e3/#text
    end
  end

  return vectors.norm(vectors.diff(freq, english.letters.freq_lower)) + penalty
end

function toolbox.replicate_to_match(piece, len)
  --[[ Replicates a piece until its length matches len.
  --
  -- - piece: Array of bytes.
  -- - len: Integer, target length.
  -- return:
  -- - Array of bytes, piece replicated to match length len.
  --]]
  result = {}
  piece_index = 0
  while #result < len do
    result[#result + 1] = piece[piece_index + 1]
    piece_index = (piece_index + 1) % #piece
  end
  return result
end

function toolbox.encode_with_key(seq, key)
  --[[ Encodes a sequence by repeating a key and xor'ing it against the sequence.
  --
  -- seq: Array of bytes, the sequence.
  -- key: Array of bytes, the key to be repeated.
  -- return:
  -- - Array of bytes, of size #seq - the encoded sequence.
  --]]
  return bytes.bytearrayxor(seq, toolbox.replicate_to_match(key, #seq))
end

function toolbox.decode_one_char_encryption(seq)
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
  scores = {}
  for i = 0, 255 do
    b = {}
    for j = 1,#seq do
      table.insert(b, i)
    end
    c = bytes.bytearrayxor(seq, b)
    text = bytes.bytearray2string(c)
    cur_score = toolbox.score_string_as_english(text)
    index = {}
    index[1] = i
    index[2] = text
    scores[index] = cur_score
  end

  kv_pairs = sorting.sort_table_by_value(scores)
  return kv_pairs
end

function toolbox.hamming_distance(a, b)
  --[[ Computes a hamming distance between two byte arrays.
  --
  -- a, b: Byte arrays, between which to compute the HD.
  -- return:
  -- - Integer, the HD.
  -- raises:
  -- - Different length exception if #a != #b.
  --]]
  assert(#a == #b, "Inputs have to be of the same length")

  hd = 0
  for i = 1, #a do
    hd = hd + bytes.popcount(bit32.bxor(a[i], b[i]))
  end
  return hd
end

function toolbox.decrypt_k_char_encoding(seq, key_size)
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
  transposed = {}
  for i = 1,key_size do
    transposed[i] = {}
  end
  for i = 1,#seq do
    table.insert(transposed[(i - 1) % key_size + 1], seq[i])
  end

  guesses = {}
  for i = 1,key_size do
    guesses[i] = toolbox.decode_one_char_encryption(transposed[i])
  end

  kv_pairs = {}
  for ind = 1,256 do
    -- Assemble the key and get average score.
    cur_key = {}
    cur_score = 0.0
    for i = 1,key_size do
      table.insert(cur_key, guesses[i][ind][1][1])
      cur_score = cur_score + guesses[i][ind][2]/key_size
    end
    -- Assemble the candidate plaintext.
    plaintext = ""
    for l = 1,#transposed[1] do
      for i = 1,key_size do
        if l <= #transposed[i] then
          plaintext = plaintext .. guesses[i][ind][1][2]:sub(l,l)
        end
      end
    end
    index = {}
    index[1] = cur_key
    index[2] = plaintext
    kv_pairs[#kv_pairs + 1] = {index, cur_score}
  end
  return kv_pairs
end

function toolbox.score_key_size_for_vigenere(seq, key_size, num_blocks)
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

  limit = math.min(num_blocks * key_size - 1, #seq)

  total_sum_hd = 0.0
  num_summands = 0
  for f_element = 1,limit,key_size do
    for s_element = f_element+key_size,limit,key_size do
      f_array = {}
      s_array = {}
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

function toolbox.decode_vigenere(seq)
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
  key_score_map = {}
  for KEY_SIZE = 1,40 do
    key_score_map[KEY_SIZE] = toolbox.score_key_size_for_vigenere(text_bytes, KEY_SIZE, 4)
  end
  key_score_pairs = sorting.sort_table_by_value(key_score_map)
  candidates = toolbox.decrypt_k_char_encoding(text_bytes, key_score_pairs[1][1])
  return candidates 
end

return toolbox
