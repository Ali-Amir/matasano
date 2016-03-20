-- @module lib.files

local files = {}
local bytes = require('lib.bytes')

function files.readfile(filename, format)
  --[[ Reads a file and returns its contents in a requested format.
  --
  -- filename: String, pathname of the file.
  -- format: String, either "byte" or "string", representing the type of format.
  --         Default is "string".
  -- return:
  -- - String, if format == "string"; contents of file interpreted as plaintext.
  -- - Array of bytes, if format == "byte"; contents of file interpreted as bytes.
  --]]
  local text = ""
  local file = io.open(filename, "r")
  for line in file:lines() do
    text = text .. "\n" .. line
  end
  file:close()

  format = format or "string"
  if format == "string" then
    return text
  else
    return bytes.string2bytearray(text)
  end
end

return files
