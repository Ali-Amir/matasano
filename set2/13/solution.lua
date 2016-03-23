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

function profile_for(email)
  --[[ Creates a profile object for a given email and returns its string
  -- representation.
  --
  -- email: String, without & and = characters. They will be ignored.
  -- return:
  -- - String, cookie representing the user object.
  --   {
  --     email: email,
  --     uid: 123,
  --     role: 'user'
  --   }
  --]]
  -- Filter & and = characters.
  email = email:gsub('&', '')
  email = email:gsub('=', '')
  -- Create a random uid.
  math.randomseed(os.time())
  local uid = math.random(1000000000)
  -- Create the mapping.
  return 'email='..email..'&uid='..uid..'&role=user'
end

print(profile_for('foo@bar'))
