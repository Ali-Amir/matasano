-- @module lib.padding.pkcs7

local pkcs7 = {}

function pkcs7.pad(msg, block_size)
  --[[ Pads a given message to have a length divisible by block_size.
  --
  -- msg: Array of bytes, the message to be padded; not modified by the method.
  -- block_size: Integer, msg should be padded to have integer multiple of
  --             block_size length.
  -- return:
  -- - Array of bytes, the padded message.
  --]]
  local padded = {}
  for i = 1,#msg do
    table.insert(padded, msg[i])
  end
  local num_pad = block_size - (#padded % block_size)
  for i = 1,num_pad do
    table.insert(padded, num_pad)
  end
  return padded
end

function pkcs7.unpad(padded_msg)
  --[[ Cancells padding applied to a message.
  --
  -- padded_msg: Array of bytes, padded message; not modified by the method.
  -- return:
  -- - Array of bytes, original message.
  --]]
  local num_pad = padded_msg[#padded_msg]
  local msg = {}
  for i = 1,(#padded_msg-num_pad) do
    table.insert(msg, padded_msg[i])
  end
  return msg
end

return pkcs7
