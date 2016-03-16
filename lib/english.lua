-- @module lib.english

local english = {}

function english.is_valid_char(ch)
  --[[ Determines if a characters is a valid character in an english sentence.
  --
  -- ch: Character.
  -- return:
  -- - Boolean, indicating whether the input is a valid character.
  --]]
  return english.is_alphanum(ch) or english.is_punctutation(ch)
end

function english.is_alphanum(ch)
  --[[ Determines if a characters is an english letter or a digit.
  --
  -- ch: Character.
  -- return:
  -- - Boolean, indicating whether the input is an english letter or a digit.
  --]]
  return english.is_alpha(ch) or english.is_digit(ch)
end

function english.is_digit(ch)
  --[[ Determines if a characters is a digit.
  --
  -- ch: Character.
  -- return:
  -- - Boolean, indicating whether the input is a digit.
  --]]
  return "0" <= ch and ch <= "9"
end

function english.is_alpha(ch)
  --[[ Determines if a characters is an english letter.
  --
  -- ch: Character.
  -- return:
  -- - Boolean, indicating whether the input is an english letter.
  --]]
  return "a" <= string.lower(ch) and string.lower(ch) <= "z"
end

function english.is_punctutation(ch)
  --[[ Determines if a characters is a punctutation sign.
  --
  -- ch: Character.
  -- return:
  -- - Boolean, indicating whether the input is a punctutation sign.
  --]]
  start_pos, end_pos = string.find(english.punctutation, "%"..ch)
  return start_pos ~= nil
end

english.punctutation = "!\"#$%&'()*+,-./:;<=>? \n"
english.letters = {}
english.letters.upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
english.letters.lower = "abcdefghijklmnopqrstuvwxyz"
english.digits = "0123456789"
english.valid_chars = english.punctutation ..
                      english.letters.upper ..
                      english.letters.lower ..
                      english.digits

english.letters.freq_lower = {
  e = 12.02,
  t = 9.10,
  a = 8.12,
  o = 7.68,
  i = 7.31,
  n = 6.95,
  s = 6.28,
  r = 6.02,
  h = 5.92,
  d = 4.32,
  l = 3.98,
  u = 2.88,
  c = 2.71,
  m = 2.61,
  f = 2.30,
  y = 2.11,
  w = 2.09,
  g = 2.03,
  p = 1.82,
  b = 1.49,
  v = 1.11,
  k = 0.69,
  x = 0.17,
  q = 0.11,
  j = 0.10,
  z = 0.07
}

english.letters.freq_upper = {
  E = 12.02,
  T = 9.10,
  A = 8.12,
  O = 7.68,
  I = 7.31,
  N = 6.95,
  S = 6.28,
  R = 6.02,
  H = 5.92,
  D = 4.32,
  L = 3.98,
  U = 2.88,
  C = 2.71,
  M = 2.61,
  F = 2.30,
  Y = 2.11,
  W = 2.09,
  G = 2.03,
  P = 1.82,
  B = 1.49,
  V = 1.11,
  K = 0.69,
  X = 0.17,
  Q = 0.11,
  J = 0.10,
  Z = 0.07
}

return english
