-- @module lib.vectors

local vectors = {}

function vectors.diff(a, b)
  --[[ Computes a component-wise difference of two vectors. In case a component
  -- is missing, it is assumed to be 0.
  --
  --  a, b: Maps of (key, Double).
  --  return:
  --  - Map with (key, a[key] - b[key]) 
  --]]
  local result = {}
  for k, v in pairs(a) do
    result[k] = v
  end
  for k, v in pairs(b) do
    if result[k] == nil then
      result[k] = 0.0
    end
    result[k] = result[k] - v
  end
  return result
end

function vectors.norm(a, norm_type)
  --[[ Computes vector norm of a vector.
  --
  -- a: Map of (key, Double).
  -- norm_type: String, type of the norm; default is l2.
  -- return:
  -- - Double, the norm.
  --]]
  norm_type = norm_type or "l2"
  if norm_type == "l2" then
    local sum = 0.0
    for k, v in pairs(a) do
      sum = sum + v*v
    end
    return sum
  end
  assert(false, "Unknown norm type")
end

return vectors
