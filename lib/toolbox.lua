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
    scores[{i, text}] = cur_score
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

return toolbox
