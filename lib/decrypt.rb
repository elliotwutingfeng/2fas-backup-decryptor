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
require 'io/console'
require 'json'
require 'openssl'

ITERATIONS = 10_000
KEY_LENGTH = 256
AUTH_TAG_LENGTH = 16
SERVICES_ENCRYPTED_FIELD_LENGTH = 3
HASH = 'sha256'.freeze
ENCRYPTION_CIPHER = 'aes-256-gcm'.freeze

# Parse `plain_text` string as JSON object

# @param [String] plain_text Encoded JSON string

# @return [BasicObject] JSON object

def parse_json(plain_text)
  JSON.parse(plain_text, symbolize_names: true)
rescue JSON::ParserError => e
  warn e.message
  exit 1
end

#
# Extract the `cipher_text_with_auth_tag`, `salt`, and `iv` bytes fields
# located at the `:servicesEncrypted` key of JSON string `content`
#
# @param [String] content JSON string
#
# @return [Hash] Fields containing data needed to decrypt the cipher text
#
def extract_fields(content)
  data = parse_json(content).fetch(:servicesEncrypted, '')
  fields = data.split(':', SERVICES_ENCRYPTED_FIELD_LENGTH + 1)
  if fields.length != SERVICES_ENCRYPTED_FIELD_LENGTH
    warn format('Invalid file. Number of fields is not %d.', SERVICES_ENCRYPTED_FIELD_LENGTH)
    exit 1
  end
  cipher_text_with_auth_tag, salt, iv = fields.map { |field| Base64.strict_decode64 field }
  { cipher_text_with_auth_tag: cipher_text_with_auth_tag, salt: salt, iv: iv }
end

# Separate cipher text from 16-byte AES-GCM authentication tag

# Reference: <https://crypto.stackexchange.com/a/63539>

# @param [String] cipher_text_with_auth_tag Cipher text with AES-GCM authentication tag as bytes

# @return [Hash] Cipher text as bytes and AES-GCM authentication tag as bytes

def split_cipher_text(cipher_text_with_auth_tag)
  if cipher_text_with_auth_tag.length <= AUTH_TAG_LENGTH
    warn format('Invalid file. Length of cipher text with auth tag must be more than %d', AUTH_TAG_LENGTH)
    exit 1
  end

  { cipher_text: cipher_text_with_auth_tag[0...-AUTH_TAG_LENGTH],
    auth_tag: cipher_text_with_auth_tag[-AUTH_TAG_LENGTH..-1] }
end

# Decrypt `cipher_text` and return the plaintext result as String

# @param [String] cipher_text Encrypted text as bytes to be decrypted

# @param [String] password Backup file password in plaintext

# @param [String] salt HMAC salt as bytes

# @param [String] iv AES-GCM initialization vector as bytes

# @param [String] auth_tag AES-GCM authentication tag as bytes

# @return [String] Decrypted `cipher_text`

def decrypt_ciphertext(cipher_text, password, salt, iv, auth_tag)
  decipher = OpenSSL::Cipher.new ENCRYPTION_CIPHER
  decipher.decrypt
  decipher.key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, ITERATIONS, KEY_LENGTH / 8,
                                            HASH)
  decipher.iv = iv
  decipher.auth_tag = auth_tag
  decipher.padding = 0

  decipher.update(cipher_text) + decipher.final
end

def main
  if ARGV.length != 1
    warn 'Usage: decrypt.rb <filename>'
    exit 1
  end

  content = File.read(ARGV[0], encoding: 'utf-8')
  cipher_text_with_auth_tag, salt, iv = extract_fields(content).values_at(:cipher_text_with_auth_tag, :salt, :iv)
  cipher_text, auth_tag = split_cipher_text(cipher_text_with_auth_tag).values_at(:cipher_text, :auth_tag)
  password = $stdin.getpass('Enter 2FAS encrypted backup password: ')
  plain_text = decrypt_ciphertext(cipher_text, password, salt, iv, auth_tag)
  parse_json(plain_text)

  puts plain_text
end

main if __FILE__ == $PROGRAM_NAME
