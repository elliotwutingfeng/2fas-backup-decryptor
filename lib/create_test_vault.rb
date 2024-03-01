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

require 'base64'

require_relative 'crypto'

#
# Encrypt vault with given AES-GCM parameters.
# If successful, return encrypted vault as JSON String.
#
# @param [String] plain_text Vault contents
# @param [String] password Vault password
# @param [String] salt HMAC salt as bytes
# @param [String] iv Vault AES-GCM initialization vector as bytes
# @param [String] reference_iv Reference AES-GCM initialization vector as bytes
#
# @return [String] Encrypted vault as JSON String
#
def encrypt_vault(plain_text, password, salt, iv, reference_iv)
  cipher_text, auth_tag = encrypt_plaintext(plain_text, password, salt, iv)
  cipher_text_with_auth_tag = Base64.strict_encode64(cipher_text + auth_tag)
  reference_cipher_text, reference_auth_tag = encrypt_plaintext(REFERENCE, password, salt, reference_iv)
  reference_cipher_text_with_auth_tag = Base64.strict_encode64(reference_cipher_text + reference_auth_tag)

  salt_b64 = Base64.strict_encode64 salt
  iv_b64 = Base64.strict_encode64 iv
  reference_iv_b64 = Base64.strict_encode64 reference_iv
  '{"services":[],"groups":[],"updatedAt":1708958781890,"schemaVersion":4,"appVersionCode":5000017,' \
    '"appVersionName":"5.3.5","appOrigin":"android","servicesEncrypted":' \
    "\"#{cipher_text_with_auth_tag}:#{salt_b64}:#{iv_b64}\"," \
    '"reference":' \
    "\"#{reference_cipher_text_with_auth_tag}:#{salt_b64}:#{reference_iv_b64}\"}"
end
