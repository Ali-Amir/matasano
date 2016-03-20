local files = require('lib.files')

lines = files.readlines("set1/8/8.txt")

min_patterns = math.huge
most_likely_line = ""

local map = {}
for i = 1,#lines do
  map[i] = {}
  local num_entries = 0
  for j = 1,#lines[i],16 do
    if map[i][lines[i]:sub(j,j+15)] == nil then
      map[i][lines[i]:sub(j,j+15)] = 0
      num_entries = num_entries + 1
    end
    map[i][lines[i]:sub(j,j+15)] = map[i][lines[i]:sub(j,j+15)] + 1
  end
  print("Patterns in line " .. i .. ": " .. num_entries)
  if (num_entries < min_patterns) then
    min_patterns = num_entries
    most_likely_line = lines[i]
  end
end

print("Min patterns: " .. min_patterns)
print("Most likely line: " .. most_likely_line)
