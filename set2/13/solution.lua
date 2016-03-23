local strings = require('lib.strings')

function parse_cookie(cookie)
  --[[ Parses a cookie string.
  --
  -- An example cookie string: 'foo=bar&baz=qux&zap=zazzle'.
  -- cookie: String, cookie to be parsed.
  -- return:
  -- - Map, key value mapping.
  --]]
  local result = {}
  local kv_pairs = strings.split(cookie, '&')
  for i = 1,#kv_pairs do
    local pair = strings.split(kv_pairs[i], '=')
    assert(#pair == 2, "Incorrect format of string: " .. kv_pairs[i])
    result[pair[1]] = pair[2]
  end
  return result
end

local map = parse_cookie('foo=bar&baz=qux&zap=zazzle')
assert(map.foo == 'bar')
assert(map.baz == 'qux')
assert(map['zap'] == 'zazzle')
