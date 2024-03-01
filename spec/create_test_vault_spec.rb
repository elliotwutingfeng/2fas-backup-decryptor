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

require 'spec_helper'
require 'create_test_vault'
require 'crypto'
require 'decrypt'

describe 'encrypt_vault' do
  it 'Encrypts vault correctly' do
    expected_plain_text = File.read('test/plaintext_test.json', :encoding => 'utf-8')
    password = 'example.com'

    SALT_AND_IV_TEST_VECTORS.each do |salt, iv|
      # String.swapcase simulates different iv for servicesEncrypted and reference.
      # In practice, for AES-GCM, both iv must be distinct and randomly generated.
      encrypted_vault = encrypt_vault(expected_plain_text, password, Base64.strict_decode64(salt),
                                      Base64.strict_decode64(iv), Base64.strict_decode64(iv.swapcase))
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
