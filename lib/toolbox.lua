-- @module lib.toolbox

local english = require('lib.english')
local vectors = require('lib.vectors')

local toolbox = {}

function toolbox.score_string_as_word(text)
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

  return vectors.norm(vectors.diff(freq, english.letters.freq_lower))
end

return toolbox
