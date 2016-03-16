local bytes = require('lib.bytes')
local toolbox = require('lib.toolbox')

function encrypt_text(text)
  --[[ Encrypts a given plaintext with key "ICE".
  --
  -- text: text to be encrypted.
  -- return:
  -- - String, hex representation of the encryption.
  --]]
  key = "ICE"
  text_bytes = bytes.string2bytearray(text)
  key_bytes = bytes.string2bytearray(key)
  cipher_bytes = toolbox.encode_with_key(text_bytes, key_bytes)
  return bytes.bytearray2hex(cipher_bytes)
end

text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
answer_mine = encrypt_text(text)
answer_expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

print("My answer       " .. answer_mine)
print("Expected answer " .. answer_expected)
assert(answer_mine == answer_expected, "Wrong answer!")
