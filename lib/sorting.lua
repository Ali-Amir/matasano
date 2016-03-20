-- @module lib.sorting

local sorting = {}

function sorting.sort_table_by_value(input_table)
  --[[ Sorts an associative table by values.
  --
  -- table: Table.
  -- return:
  -- - Array of tuples, sorted array.
  --]]
  local kv_pairs = {}
  for k,v in pairs(input_table) do
    table.insert(kv_pairs, {k, v})
  end

  function compare(a,b)
    return a[2] < b[2]
  end
  table.sort(kv_pairs, compare)
  return kv_pairs
end

return sorting
