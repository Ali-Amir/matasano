local bytes = require('lib.bytes')
local strings = require('lib.strings')
local toolbox = require('lib.toolbox')

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

enc_oracle, dec_oracle = toolbox.new_encryption_oracle_aes_ecb('')
-- Input to be modified for the attack.
input = bytes.bytearray2string(toolbox.replicate_to_match({string.byte('A')}, 10)) ..
        'admin' ..
        bytes.bytearray2string(toolbox.replicate_to_match({11}, 11)) ..
        bytes.bytearray2string(toolbox.replicate_to_match({string.byte('A')}, 12))
-- Encryption to be played with for the attack.
enc = bytes.bytearray2string(enc_oracle(bytes.string2bytearray(profile_for(input))))
enc = bytes.string2bytearray(enc:sub(1,16) .. enc:sub(33,64) .. enc:sub(17,32))
-- Decryption of the attack.
dec = bytes.bytearray2string(dec_oracle(enc))
print(dec)
