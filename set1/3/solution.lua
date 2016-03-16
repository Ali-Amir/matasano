local bytes = require('lib.bytes')
local english = require('lib.english')
local vectors = require('lib.vectors')
local sorting = require('lib.sorting')

function score_string_as_word(text)
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
    if "a" <= ch and ch <= "z" then
      if freq[ch] == nil then
        freq[ch] = 0.0
      end
      freq[ch] = freq[ch] + 1.0 / #text
    end
  end

  return vectors.norm(vectors.diff(freq, english.letters.freq_lower))
end

cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
punctutation = "!\"#$%&'()*+,-./:;<=>? "
scores = {}
for i = 0, 255 do
  a = bytes.hex2bytearray(cipher)
  b = {}
  for j = 1,#a do
    table.insert(b, i)
  end
  c = bytes.bytearrayxor(a, b)
  text = bytes.bytearray2string(c)
  cur_score = score_string_as_word(text)
  has_invalid_characters = false
  for i = 1,#text do
    ch = text:sub(i, i)
    if "a" <= string.lower(ch) and string.lower(ch) <= "z" then
    elseif "0" <= ch and ch <= "9" then
    else
      is_punctutation = false
      for j = 1,#punctutation do
        if punctutation:sub(j,j) == ch then
          is_punctutation = true
          break
        end
      end
      if not is_punctutation then
        cur_score = math.huge
      end
    end
  end

  scores[text] = cur_score
end

kv_pairs = sorting.sort_table_by_value(scores)
for i = 1,1 do
  print(kv_pairs[i][1] .. " " .. kv_pairs[i][2])
end
