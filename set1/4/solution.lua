local bytes = require('lib.bytes')
local english = require('lib.english')
local sorting = require('lib.sorting')
local toolbox = require('lib.toolbox')

io.input("set1/4/4.txt")

scores = {}

while true do
  local cipher = io.read()
  if cipher == nil then break end

  for i = 0, 255 do
    a = bytes.hex2bytearray(cipher)
    b = {}
    for j = 1,#a do
      table.insert(b, i)
    end
    c = bytes.bytearrayxor(a, b)
    text = bytes.bytearray2string(c)
    cur_score = toolbox.score_string_as_word(text)
    has_invalid_characters = false
    for i = 1,#text do
      ch = text:sub(i, i)
      if not english.is_valid_char(ch) then
        -- cur_score = math.huge
        cur_score = cur_score + 1000.0
        break
      end
    end

    scores[text] = cur_score
  end
end

kv_pairs = sorting.sort_table_by_value(scores)
for i = 1,1 do
  print(kv_pairs[i][1] .. " " .. kv_pairs[i][2])
end
