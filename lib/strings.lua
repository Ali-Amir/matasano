-- @module lib.strings

local strings = {}

function strings.split(str, char)
  --[[ Splits the string, given separation character.
  --
  -- str: String, string to be splitted; not actually modified.
  -- char: Character, delimiter character.
  -- return:
  -- - Array of strings, string after splitting.
  --]]
  local result = {}
  local accum = ""
  for i = 1,#str do
    if str:sub(i,i) == char then
      table.insert(result, accum)
      accum = ""
    else
      accum = accum .. str:sub(i,i)
    end
  end
  table.insert(result, accum)
  return result
end

return strings
