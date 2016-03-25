local aes = require('lib.block_ciphers.aes')
local bytes = require('lib.bytes')
local cbc = require('lib.modes.cbc')
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
  local kv_pairs = strings.split(cookie, ';')
  for i = 1,#kv_pairs do
    local pair = strings.split(kv_pairs[i], '=')
    assert(#pair == 2, "Incorrect format of string: " .. kv_pairs[i])
    result[pair[1]] = pair[2]
  end
  return result
end

function new_encryption_oracle_aes_cbc(append_bytes, extra_args)
  --[[ Creates a new encryption oracle that encrypts given data under
  -- AES-128-cbc.
  --
  -- Generates a random key for AES and returns an encryptor that encrypts under
  -- that key, as well as the decryptor.
  --
  -- append_bytes: Byte array, pattern to be appended when encrypting:
  --              E(input || append_bytes, key).
  -- extra_args: Table, extra arguments:
  --             - random_prepend: Boolean, whether to add a random prefix
  --                               E(random_prepend||input||append_bytes, key);
  --                               requires prepend_range to be set; defaults
  --                               to false.
  --             - preprend_range: Pair of integers, range of length of prepend
  --                               to sample from; defaults to nil.
  -- return:
  -- - Function, the encryption oracle.
  -- - Function, the decryption oracle.
  --]]
  extra_args = extra_args or {}
  extra_args.random_prepend = extra_args.random_prepend or false
  assert(not extra_args.random_prepend or extra_args.prepend_range ~= nil,
         "Prepend range needs to be set!")
  assert(type(append_bytes) == 'table', "Incorrect input type: " .. type(append_bytes))

  -- Generate the key one byte at a time.
  local key = bytes.random_bytearray(16)
  function aes_cbc_encryptor(data_org)
    --[[ An encryption oracle that encrypts given data under AES-128-cbc.
    --
    -- data_org: Array of bytes, original data; not modified.
    -- return:
    -- - Array of bytes, the encrypted text.
    --]]
    assert(type(data_org) == 'table', 'Incorrect input type: ' .. type(data_org))
    -- Initialize the data.
    local data = {}
    data = bytes.string2bytearray('comment1=cooking%20MCs;userdata=')
    for i = 1,#data_org do
      table.insert(data, data_org[i])
    end
    for i = 1,#append_bytes do
      table.insert(data, append_bytes[i])
    end
    return cbc.encrypt(data, key, aes)
  end
  function aes_cbc_decryptor(ciphertext)
    --[[ An encryption oracle that decrypts given ciphertext under AES-128-cbc.
    --
    -- ciphertext: Array of bytes, original data; not modified.
    -- return:
    -- - Array of bytes, the decrypted text.
    --]]
    assert(type(ciphertext) == 'table', 'Incorrect input type: ' .. type(ciphertext))
    return cbc.decrypt(ciphertext, key, aes)
  end
  return aes_cbc_encryptor, aes_cbc_decryptor
end

math.randomseed(os.time())

enc_or, dec_or = new_encryption_oracle_aes_cbc(bytes.string2bytearray(';comment2=%20like%20a%20pound%20of%20bacon'))
attack_bytes = bytes.string2bytearray(string.rep('A', 16) .. 'AadminBtrue')
encrypted_bytes = enc_or(attack_bytes)
encrypted_bytes[32 + 1] = encrypted_bytes[32 + 1] ~ string.byte('A') ~ string.byte(';')
encrypted_bytes[32 + 7] = encrypted_bytes[32 + 7] ~ string.byte('B') ~ string.byte('=')
parsed = bytes.bytearray2string(dec_or(encrypted_bytes))
print("Parsed: " .. parsed)
obj = parse_cookie(parsed)
print(obj.admin)
