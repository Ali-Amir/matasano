-- @module lib.toolbox

local aes = require('lib.block_ciphers.aes')
local bytes = require('lib.bytes')
local ecb = require('lib.modes.ecb')
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
  local freq = {}
  for i = 1,#text do
    local ch = string.lower(text:sub(i, i))
    if english.is_alpha(ch) then
      if freq[ch] == nil then
        freq[ch] = 0.0
      end
      freq[ch] = freq[ch] + 1.0 / #text
    end
  end

  local penalty = 0.0
  for i = 1,#text do
    local ch = text:sub(i, i)
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
  local result = {}
  local piece_index = 0
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

  local hd = 0
  for i = 1, #a do
    hd = hd + bytes.popcount(bit32.bxor(a[i], b[i]))
  end
  return hd
end

function toolbox.new_encryption_oracle_aes_ecb(append_bytes, extra_args)
  --[[ Creates a new encryption oracle that encrypts given data under
  -- AES-128-ECB.
  --
  -- Generates a random key for AES and returns an encryptor that encrypts under
  -- that key, as well as the decryptor.
  --
  -- append_bytes: Byte array, pattern to be appended when encrypting:
  --              E(input || append_bytes, key).
  -- extra_args: Table, extra arguments:
  --             - random_prepend: Boolean, whether to add a random prefix
  --                               E(random_prepend||input||append_bytes, key);
  --                               requires prepend_range to be set; defaults
  --                               to false.
  --             - preprend_range: Pair of integers, range of length of prepend
  --                               to sample from; defaults to nil.
  -- return:
  -- - Function, the encryption oracle.
  -- - Function, the decryption oracle.
  --]]
  extra_args = extra_args or {}
  extra_args.random_prepend = extra_args.random_prepend or false
  assert(not extra_args.random_prepend or extra_args.prepend_range ~= nil,
         "Prepend range needs to be set!")
  assert(type(append_bytes) == 'table', "Incorrect input type: " .. type(append_bytes))

  -- Generate the key one byte at a time.
  math.randomseed(os.time())
  local key = bytes.random_bytearray(16)
  function aes_ecb_encryptor(data_org)
    --[[ An encryption oracle that encrypts given data under AES-128-ECB.
    --
    -- data_org: Array of bytes, original data; not modified.
    -- return:
    -- - Array of bytes, the encrypted text.
    --]]
    assert(type(data_org) == 'table', 'Incorrect input type: ' .. type(data_org))
    -- Initialize the data.
    local data = {}
    if extra_args.random_prepend then
      data = bytes.random_bytearray(math.random(extra_args.prepend_range[1],
                                                extra_args.prepend_range[2]))
    end
    for i = 1,#data_org do
      table.insert(data, data_org[i])
    end
    for i = 1,#append_bytes do
      table.insert(data, append_bytes[i])
    end
    return ecb.encrypt(data, key, aes)
  end
  function aes_ecb_decryptor(ciphertext)
    --[[ An encryption oracle that decrypts given ciphertext under AES-128-ECB.
    --
    -- ciphertext: Array of bytes, original data; not modified.
    -- return:
    -- - Array of bytes, the decrypted text.
    --]]
    assert(type(ciphertext) == 'table', 'Incorrect input type: ' .. type(ciphertext))
    return ecb.decrypt(ciphertext, key, aes)
  end
  return aes_ecb_encryptor, aes_ecb_decryptor
end

function toolbox.gcd(a, b)
  --[[ Determines gcd(a, b).
  --
  -- a, b: Integer, inputs to the function.
  -- return:
  -- - Integer, gcd(a, b).
  --]]
  if a == 0 then
    return b
  end
  return toolbox.gcd(b % a, a)
end

return toolbox
