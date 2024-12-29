# CLI tool to decrypt backup files exported from the 2FAS Authenticator app
# Copyright (C) 2024 Wu Tingfeng <wutingfeng@outlook.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

require 'create_test_vault'
require 'crypto'
require 'spec_helper'

# salt and iv are randomly generated via `[OpenSSL::Random.random_bytes(LENGTH)].pack('m0')` where
# `LENGTH` is 256 for salt and 12 for iv.
SALT_AND_IV_TEST_VECTORS = [
  [
    'ZV0cVL+4EPjkJ8X4sEoja38u9BbAf8PX5rNCrBHrJgaUlSvmS7xKtgbhD8bmZNf5vhQyVVXIge/oAC/PKosEBrtfZ8HAYeSsqV' \
    'wg9tEr5V+NG1EV+o7F0y94agQvyTBjLRP/8nYJwnoNuEO3oK9AqAqmfSBjCgSZNzFPsjp9wh896GsMr/VOl3proD9btsc4H' \
    'HG/0RB0KMtTaWYd3lMfHUPzHDDwvlXOiEJNJNhEzCk6qa5ISI+6hNbgsPhlWowHvBV8+WJKa2w4jceAKXP8w/ftESHZRabw' \
    'iMrGJsXoZ0FobI2Xq0gfcEy06LUrf08b6b8Tt0JEtkc+RZ0ncyUMaA==', '6/dS+1PWwlE8Jwuy'
  ], ['GlnfpJEabZKxXQsI/DKzPK90dQwRl9z1jZuGTjKhPBBF+SpWaQiHhT2b6Tu4l/I06+f1pRL8WsUqCXOar0MQo3MgG0kl' \
      'ybPP8HL8h2Pj6wCqDSwTxQIU2pIxDtLC30rIdfbDBAn63pzDhPY1R//zRy5LbL3dpY/5AERYUF1A1Osxc7TnWDExjUBbK/kvN' \
      '6vZwlVcwpHcnzgX0ota7yC1yY0mZ4ek7gn/WaLwWZoyFK4qYZlVON4Zo8olpH3J/D8uRyN0/raqCvCgunPxtr7MwzJJ1uyoz7' \
      'PbqqLq7Jh3gjtjt80j1gVUM0QAUQwLeQlJABg9rHXjatoZZClfLi/lCg==', 'c9Rrz0ywTPZ3sBUi'],
  ['Jljh8tr1hrFYla54digxTTJyrx0ISp4z/jjgptBqiHB/WQkqgqpraAe9WS0pir8jXRYYctocMyrYOqPlaoRyeMkd027Pt18Ob' \
   'SxCM7M3jV87WTBDuiqmwjm9oLvZCflALQUmQjOWVdLz5rg6Qa2d1alSP5zRiOIrtgADdbfa1VGzScNRPhxl1XuRlm5NVyk2wvbMy' \
   'cwxUTQP3YLrzI2afXk9evZCJSbpsap6Kjv9iI2ztuMF7jIloQC/SUs/0qJGXbHToLgTklr3GoQgSpCECUbjeH1e3m+Z8TNedv2qv' \
   'QDxrkiP6FPJYvOaOFVM6PGbrUMflif8gR2oMdxzQ2xZVg==', 'tUNqsK9OSBXrbLCS']
].freeze

describe 'encrypt_vault' do
  it 'Encrypts vault correctly' do
    expected_plain_text = File.read('test/plaintext_test.json', :encoding => 'utf-8')
    password = 'example.com'

    SALT_AND_IV_TEST_VECTORS.each do |salt, iv|
      # String.swapcase simulates different iv for servicesEncrypted and reference.
      # In practice, for AES-GCM, both iv must be distinct and randomly generated.
      encrypted_vault = encrypt_vault(expected_plain_text, password, salt.unpack1('m0'),
                                      iv.unpack1('m0'), iv.swapcase.unpack1('m0'))
      # Now decrypt it and check that its plaintext form matches the expected plaintext.
      obj = parse_json encrypted_vault
      cipher_text_with_auth_tag, salt, iv = extract_fields(obj).values_at(:cipher_text_with_auth_tag, :salt, :iv)
      cipher_text, auth_tag = split_cipher_text(cipher_text_with_auth_tag).values_at(:cipher_text, :auth_tag)
      plain_text, = decrypt_ciphertext(cipher_text, password, salt, iv, auth_tag)
      expect(plain_text).to eq expected_plain_text
    end
  end
end

describe 'encrypt_plaintext' do
  it 'Fails to encrypt empty plaintext' do
    silence('stderr') do
      expect { encrypt_vault('', '', '', '', '') }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
    end
  end
end
