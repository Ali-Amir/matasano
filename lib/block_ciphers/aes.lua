-- @module lib.block_ciphers.aes

local bytes = require('lib.bytes')
local GF256 = require('lib.finite_fields').GF256

local aes = {}

local AESMat = {}

AESMat.sbox = {
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}

AESMat.inv_sbox = {
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}

function AESMat:new(block)
  --[[ Creates a new instance of AESMat object initialized from a block.
  --
  -- block: Array of bytes, of length 16; is not modified.
  -- return:
  -- - AESMat object, representing a 4x4 matrix.
  --]]
  local a = {}
  a[1] = {block[1], block[5], block[9], block[13]}
  a[2] = {block[2], block[6], block[10], block[14]}
  a[3] = {block[3], block[7], block[11], block[15]}
  a[4] = {block[4], block[8], block[12], block[16]}
  local mat = {}
  mat.a = a
  setmetatable(mat, {__index = AESMat})
  return mat
end

function AESMat:add(mat)
  --[[ Applies an element-wise xor with mat on self.
  --
  -- mat: AESMat object, 4x4 matrix to xor against.
  -- return:
  -- - AESMat object, self after the xor.
  --]]
  for i = 1,4 do
    for j = 1,4 do
      self.a[i][j] = self.a[i][j] ~ mat.a[i][j]
    end
  end
  return self
end

function AESMat:sub_bytes()
  --[[ Applies substitution step on AESMat, as described here:
  -- https://en.wikipedia.org/wiki/Rijndael_S-box
  --
  -- return:
  -- - AESMat object, self after SubBytes applied.
  --]]
  for i = 1,4 do
    for j = 1,4 do
      self.a[i][j] = self.sbox[self.a[i][j] + 1]
    end
  end
  return self
end

function AESMat:inv_sub_bytes()
  --[[ Applies inverse substitution step on AESMat, as described here:
  -- https://en.wikipedia.org/wiki/Rijndael_S-box
  --
  -- return:
  -- - AESMat object, self after InvSubBytes applied.
  --]]
  for i = 1,4 do
    for j = 1,4 do
      self.a[i][j] = self.inv_sbox[self.a[i][j] + 1]
    end
  end
  return self
end

function AESMat:shift_rows()
  --[[ Applies shift rows step on AESMat, as described here:
  -- https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
  --
  -- return:
  -- - AESMat object, self after ShiftRows applied.
  --]]
  self.a[2] = {self.a[2][2], self.a[2][3], self.a[2][4], self.a[2][1]}
  self.a[3] = {self.a[3][3], self.a[3][4], self.a[3][1], self.a[3][2]}
  self.a[4] = {self.a[4][4], self.a[4][1], self.a[4][2], self.a[4][3]}
  return self
end

function AESMat:inv_shift_rows()
  --[[ Applies inverse shift rows step on AESMat, as described here:
  -- https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
  --
  -- return:
  -- - AESMat object, self after InvShiftRows applied.
  --]]
  self.a[2] = {self.a[2][4], self.a[2][1], self.a[2][2], self.a[2][3]}
  self.a[3] = {self.a[3][3], self.a[3][4], self.a[3][1], self.a[3][2]}
  self.a[4] = {self.a[4][2], self.a[4][3], self.a[4][4], self.a[4][1]}
  return self
end

function AESMat:mix_columns()
  --[[ Applies mix columns step on AESMat, as described here:
  -- https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
  -- 
  -- return:
  -- - AESMat object, self after applying MixColumns.
  --]]
  local sp = {}
  -- First row.
  sp[1] = {0, 0, 0, 0}
  for j = 1,4 do
    sp[1][j] = GF256:new(0x02):mul(GF256:new(self.a[1][j])).v ~
               GF256:new(0x03):mul(GF256:new(self.a[2][j])).v ~ 
               self.a[3][j] ~ self.a[4][j]
  end
  -- Second row.
  sp[2] = {0, 0, 0, 0}
  for j = 1,4 do
    sp[2][j] = GF256:new(0x02):mul(GF256:new(self.a[2][j])).v ~
               GF256:new(0x03):mul(GF256:new(self.a[3][j])).v ~ 
               self.a[1][j] ~ self.a[4][j]
  end
  -- Third row.
  sp[3] = {0, 0, 0, 0}
  for j = 1,4 do
    sp[3][j] = GF256:new(0x02):mul(GF256:new(self.a[3][j])).v ~
               GF256:new(0x03):mul(GF256:new(self.a[4][j])).v ~ 
               self.a[1][j] ~ self.a[2][j]
  end
  -- Fourth row.
  sp[4] = {0, 0, 0, 0}
  for j = 1,4 do
    sp[4][j] = GF256:new(0x02):mul(GF256:new(self.a[4][j])).v ~
               GF256:new(0x03):mul(GF256:new(self.a[1][j])).v ~ 
               self.a[2][j] ~ self.a[3][j]
  end
  self.a = sp
  return self
end

function AESMat:inv_mix_columns()
  --[[ Applies inverse mix columns step on AESMat, as described here:
  -- https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
  -- 
  -- return:
  -- - AESMat object, self after applying InvMixColumns.
  --]]
  local sp = {}
  -- First row.
  sp[1] = {0, 0, 0, 0}
  for j = 1,4 do
    sp[1][j] = GF256:new(0x0E):mul(GF256:new(self.a[1][j])).v ~
               GF256:new(0x0B):mul(GF256:new(self.a[2][j])).v ~ 
               GF256:new(0x0D):mul(GF256:new(self.a[3][j])).v ~ 
               GF256:new(0x09):mul(GF256:new(self.a[4][j])).v
  end
  -- Second row.
  sp[2] = {0, 0, 0, 0}
  for j = 1,4 do
    sp[2][j] = GF256:new(0x09):mul(GF256:new(self.a[1][j])).v ~
               GF256:new(0x0E):mul(GF256:new(self.a[2][j])).v ~ 
               GF256:new(0x0B):mul(GF256:new(self.a[3][j])).v ~ 
               GF256:new(0x0D):mul(GF256:new(self.a[4][j])).v
  end
  -- Third row.
  sp[3] = {0, 0, 0, 0}
  for j = 1,4 do
    sp[3][j] = GF256:new(0x0D):mul(GF256:new(self.a[1][j])).v ~
               GF256:new(0x09):mul(GF256:new(self.a[2][j])).v ~ 
               GF256:new(0x0E):mul(GF256:new(self.a[3][j])).v ~ 
               GF256:new(0x0B):mul(GF256:new(self.a[4][j])).v
  end
  -- Fourth row.
  sp[4] = {0, 0, 0, 0}
  for j = 1,4 do
    sp[4][j] = GF256:new(0x0B):mul(GF256:new(self.a[1][j])).v ~
               GF256:new(0x0D):mul(GF256:new(self.a[2][j])).v ~ 
               GF256:new(0x09):mul(GF256:new(self.a[3][j])).v ~ 
               GF256:new(0x0E):mul(GF256:new(self.a[4][j])).v
  end
  self.a = sp
  return self
end

local KeyScheduler = {}

function KeyScheduler:g(round, word)
  --[[ Computes g of a given word as described here:
  -- https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
  --
  -- round: Integer, current round.
  -- word: Array of bytes, 4 bytes that constitute the word; does not modify input.
  -- return:
  -- - Array of bytes, output word.
  --]]
  word = {word[2], word[3], word[4], word[1]}
  for i = 1,4 do
    word[i] = AESMat.sbox[word[i] + 1]
  end
  word[1] = word[1] ~ self.rcon[round]
  return word
end

function KeyScheduler:cur_round_key(round, prev_key)
  --[[ Computes the key for the current round, given the key for the previous round.
  --
  -- round: Integer, current round.
  -- prev_key: AESMat object, representing the key of the previous round.
  -- return:
  -- - AESMat object, representing the key of the next round.
  --]]
  local new_a = {}
  local g = self:g(round, {prev_key.a[1][4], prev_key.a[2][4], prev_key.a[3][4], prev_key.a[4][4]})
  new_block = {}
  for i = 1,4 do
    new_block[0*4 + i] = g[i] ~ prev_key.a[i][1]
  end
  for i = 1,4 do
    new_block[1*4 + i] = new_block[0*4 + i] ~ prev_key.a[i][2]
  end
  for i = 1,4 do
    new_block[2*4 + i] = new_block[1*4 + i] ~ prev_key.a[i][3]
  end
  for i = 1,4 do
    new_block[3*4 + i] = new_block[2*4 + i] ~ prev_key.a[i][4]
  end
  return AESMat:new(new_block)
end

function KeyScheduler:new(key)
  --[[ Creates a new KeyScheduler initialized with given key.
  --
  -- key: AESMat object, initialization key.
  -- return:
  -- - KeyScheduler object.
  --]]
  local ks = {}
  setmetatable(ks, {__index = KeyScheduler})
  ks.rcon = {}
  ks.rcon[1] = 0x01
  for round = 2,10 do
    ks.rcon[round] = (GF256:new(ks.rcon[round - 1])):mul(GF256:new(0x02)).v
  end

  local block = {}
  for j = 1,4 do
    for i = 1,4 do
      table.insert(block, key.a[i][j])
    end
  end

  ks.keys = {}
  ks.keys[0] = AESMat:new(block)
  for round = 1,10 do
    ks.keys[round] = ks:cur_round_key(round, ks.keys[round - 1])
  end
  return ks
end

function KeyScheduler:get_key(round)
  --[[ Returns a key for a given round.
  --
  -- round: Integer, round number between [0..12).
  -- return:
  -- - Array of bytes, 4 bytes representing the key word of a round.
  --]]
  return self.keys[round]
end

function aes.encrypt(block, key)
  --[[ Encrypts a block of size 128 bits with a key key under AES:
  -- https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
  --
  -- block: Array of bytes, of length 16, the plaintext to be encrypted.
  -- key: Integer, key of encryption.
  -- return:
  -- - Array of bytes, the ciphertext.
  --]]
  -- 0. Initialize variables.
  local rounds = 10 
  local input_state = AESMat:new(block)
  local key_mat = AESMat:new(key)
  local key_scheduler = KeyScheduler:new(key_mat)
  -- 1. Add round key.
  local round_key = key_scheduler:get_key(0)
  input_state:add(round_key)
  -- 2. Do the rounds.
  for round = 1,rounds do
    -- 2.1. Substitute bytes.
    input_state:sub_bytes()
    -- 2.2. Shift rows.
    input_state:shift_rows()
    -- 2.3. Mix rows.
    if round ~= rounds then
      input_state:mix_columns()
    end
    -- 2.4. Add round key.
    round_key = key_scheduler:get_key(round)
    input_state:add(round_key)
  end
  -- Get the final state into a byte array.
  ciphertext = {}
  for j = 1,4 do
    for i = 1,4 do
      ciphertext[(j - 1)*4 + i] = input_state.a[i][j]
    end
  end
  return ciphertext
end

function aes.decrypt(ciphertext, key)
  --[[ Decrypts a block of size 128 bits with a key key under AES:
  -- https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
  --
  -- ciphertext: Array of bytes, of length 16, the ciphertext to be decrypted.
  -- key: Integer, key of encryption.
  -- return:
  -- - Array of bytes, the plaintext.
  --]]
  -- 0. Initialize variables.
  local rounds = 10 
  local input_state = AESMat:new(ciphertext)
  local key_mat = AESMat:new(key)
  local key_scheduler = KeyScheduler:new(key_mat)
  -- 1. Add round key.
  local round_key = key_scheduler:get_key(rounds - 0)
  input_state:add(round_key)
  -- 2. Do the rounds.
  for round = 1,rounds do
    -- 2.1. Inverse shift rows.
    input_state:inv_shift_rows()
    -- 2.2. Inverse substitute bytes.
    input_state:inv_sub_bytes()
    -- 2.3. Add round key.
    round_key = key_scheduler:get_key(rounds - round)
    input_state:add(round_key)
    -- 2.4. Inverse mix columns.
    if round ~= rounds then
      input_state:inv_mix_columns()
    end
  end
  -- Get the final state into a byte array.
  ciphertext = {}
  for j = 1,4 do
    for i = 1,4 do
      ciphertext[(j - 1)*4 + i] = input_state.a[i][j]
    end
  end
  return ciphertext
end

aes.AESMat = AESMat
aes.KeyScheduler = KeyScheduler

return aes
