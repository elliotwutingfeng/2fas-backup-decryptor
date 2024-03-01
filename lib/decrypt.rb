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
require 'openssl'
require 'optparse'

require_relative 'pretty'

ITERATIONS = 10_000
KEY_LENGTH = 256
AUTH_TAG_LENGTH = 16
SERVICES_ENCRYPTED_FIELD_LENGTH = 3
HASH = 'sha256'.freeze
ENCRYPTION_CIPHER = 'aes-256-gcm'.freeze

# https://github.com/twofas/2fas-android/blob/main/data/services/src/main/java/com/twofasapp/data/services/domain/BackupContent.kt
REFERENCE = 'tRViSsLKzd86Hprh4ceC2OP7xazn4rrt4xhfEUbOjxLX8Rc3mkISXE0lWbmnWfggogbBJhtYgpK6fMl1D6m' \
            'tsy92R3HkdGfwuXbzLebqVFJsR7IZ2w58t938iymwG4824igYy1wi6n2WDpO1Q1P69zwJGs2F5a1qP4MyIiDSD7NCV2OvidX' \
            'QCBnDlGfmz0f1BQySRkkt4ryiJeCjD2o4QsveJ9uDBUn8ELyOrESv5R5DMDkD4iAF8TXU7KyoJujd'.freeze

def terminate(message)
  warn message
  exit 1
end

def assert_is_hash(obj)
  return if obj.is_a? Hash

  terminate 'Invalid vault file. Top-level is not Hash.'
end

#
# Extract the `cipher_text_with_auth_tag`, `salt`, and `iv` bytes fields
# located at the `:servicesEncrypted` key of JSON Hash `obj`.
#
# @param [Hash] obj JSON Hash
#
# @return [Hash] Fields containing data needed to decrypt the cipher text
#
def extract_fields(obj)
  assert_is_hash(obj)
  fields = obj.fetch(:servicesEncrypted, '').split(':', SERVICES_ENCRYPTED_FIELD_LENGTH + 1)
  if fields.length != SERVICES_ENCRYPTED_FIELD_LENGTH
    terminate format('Invalid vault file. Number of fields is not %d.', SERVICES_ENCRYPTED_FIELD_LENGTH)
  end
  cipher_text_with_auth_tag, salt, iv = fields.map { |field| Base64.strict_decode64 field }
  { :cipher_text_with_auth_tag => cipher_text_with_auth_tag, :salt => salt, :iv => iv }
end

#
# Separate cipher text from 16-byte AES-GCM authentication tag.
# Reference: https://crypto.stackexchange.com/a/63539
#
# @param [String] cipher_text_with_auth_tag Cipher text with AES-GCM authentication tag as bytes
#
# @return [Hash] Cipher text as bytes and AES-GCM authentication tag as bytes
#
def split_cipher_text(cipher_text_with_auth_tag)
  if cipher_text_with_auth_tag.length <= AUTH_TAG_LENGTH
    terminate format('Invalid vault file. Length of cipher text with auth tag must be more than %d', AUTH_TAG_LENGTH)
  end

  { :cipher_text => cipher_text_with_auth_tag[0...-AUTH_TAG_LENGTH],
    :auth_tag => cipher_text_with_auth_tag[-AUTH_TAG_LENGTH..-1] }
end

#
# Derive a key from the given password and salt using PBKDF2-HMAC.
#
# @param [String] password Backup file password as plaintext
# @param [String] salt HMAC salt as bytes
#
# @return [String] Derived key
#
def derive_key(password, salt)
  OpenSSL::PKCS5.pbkdf2_hmac(password, salt, ITERATIONS, KEY_LENGTH / 8,
                             HASH)
end

#
# Perform AES-GCM encryption or decryption.
#
# @param [String] text Text to be encrypted or decrypted
# @param [String] master_key AES-GCM master key
# @param [String] iv AES-GCM initialization vector
# @param [Boolean] encrypt Specify whether encryption or decryption should be performed
# @param [String, nil] auth_tag AES-GCM authentication tag used for decryption. Will not be used if `encrypt` is true.
#
# @return [Array<String>] 2-element Array where first element is resulting ciphertext or plaintext, and second element
#  is the AES-GCM authentication tag
#
def aes_gcm(text, master_key, iv, encrypt, auth_tag = nil)
  cipher = OpenSSL::Cipher.new ENCRYPTION_CIPHER
  if encrypt
    cipher.encrypt
  else
    cipher.decrypt
  end
  cipher.key = master_key
  cipher.iv = iv
  cipher.auth_tag = auth_tag unless encrypt
  cipher.auth_data = ''
  cipher.padding = 0

  [cipher.update(text) + cipher.final, encrypt ? cipher.auth_tag : auth_tag]
end

#
# Decrypt `cipher_text` and return its plaintext and authentication tag.
#
# @param [String] cipher_text Encrypted text as bytes to be decrypted
# @param [String] password Backup file password as plaintext
# @param [String] salt HMAC salt as bytes
# @param [String] iv AES-GCM initialization vector as bytes
# @param [String] auth_tag AES-GCM authentication tag as bytes
#
# @return [Array<String>] 2-element Array where first element is resulting plaintext, and second element
#  is the AES-GCM authentication tag
#
def decrypt_ciphertext(cipher_text, password, salt, iv, auth_tag)
  encrypt = false
  master_key = derive_key(password, salt)
  aes_gcm(cipher_text, master_key, iv, encrypt, auth_tag)
rescue OpenSSL::Cipher::CipherError, ArgumentError => e
  terminate "Failed to derive cipher key. #{e.instance_of?(ArgumentError) ? e.message : 'Wrong password?'}"
end

#
# Encrypt `plain_text` and return its ciphertext and authentication tag.
#
# @param [String] plain_text bytes to be encrypted
# @param [String] password Backup file password as plaintext
# @param [String] salt HMAC salt as bytes
# @param [String] iv AES-GCM initialization vector as bytes
#
# @return [Array<String>] 2-element Array where first element is resulting ciphertext, and second element
#  is the AES-GCM authentication tag
#
def encrypt_plaintext(plain_text, password, salt, iv)
  encrypt = true
  master_key = derive_key(password, salt)
  aes_gcm(plain_text, master_key, iv, encrypt)
rescue OpenSSL::Cipher::CipherError, ArgumentError => e
  terminate "Failed to encrypt plaintext. #{e.instance_of?(ArgumentError) ? e.message : 'Invalid parameters?'}"
end

#
# Prompt terminal user for password.
# A drop-in replacement for $stdin.getpass for older Ruby versions.
#
# @param [String] prompt Message prompt to display
#
# @return [String] Password as plaintext
#
def getpass(prompt)
  $stderr.write prompt # Display prompt without adding prompt to stdout.
  password = $stdin.noecho(&:gets).chomp
  $stderr.puts # Display newline without adding newline to stdout.
  password
end

#
# Decrypt vault with password from user input.
# If successful, return plaintext vault data as JSON String.
#
# @param [String] filename Vault file to decrypt
#
# @return [String] Plaintext vault as JSON String
#
def decrypt_vault(filename)
  begin
    obj = parse_json File.read(filename, :encoding => 'utf-8')
  rescue Errno::ENOENT => e
    terminate e.to_s
  end
  cipher_text_with_auth_tag, salt, iv = extract_fields(obj).values_at(:cipher_text_with_auth_tag, :salt, :iv)
  cipher_text, auth_tag = split_cipher_text(cipher_text_with_auth_tag).values_at(:cipher_text, :auth_tag)

  password = getpass('Enter 2FAS encrypted backup password: ')
  plain_text, = decrypt_ciphertext(cipher_text, password, salt, iv, auth_tag)
  parse_json(plain_text) # Ensure plain_text is valid JSON.
  plain_text
end

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
  cipher_text, auth_tag = encrypt_plaintext(plain_text, password, Base64.strict_decode64(salt),
                                            Base64.strict_decode64(iv))
  cipher_text_with_auth_tag = Base64.strict_encode64(cipher_text + auth_tag)
  reference_cipher_text, reference_auth_tag = encrypt_plaintext(REFERENCE, password, Base64.strict_decode64(salt),
                                                                Base64.strict_decode64(reference_iv))
  reference_cipher_text_with_auth_tag = Base64.strict_encode64(reference_cipher_text + reference_auth_tag)
  '{"services":[],"groups":[],"updatedAt":1708958781890,"schemaVersion":4,"appVersionCode":5000017,' \
    '"appVersionName":"5.3.5","appOrigin":"android","servicesEncrypted":' \
    "\"#{cipher_text_with_auth_tag}:#{salt}:#{iv}\"," \
    '"reference":' \
    "\"#{reference_cipher_text_with_auth_tag}:#{salt}:#{reference_iv}\"}"
end

#
# Accept vault filename as a command-line argument, and optionally output format.
# Decrypt the vault and write its contents to $stdout in specified output format.
#
# @param [String] filename Vault file to decrypt
# @param [String] format Output format (Default: json)
#
def main
  formats = %i[json csv pretty]
  options = { :format => :json, :except => [] }

  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} <filename> [options]"
    opts.on('-f FORMAT', '--format FORMAT', formats,
            "Plaintext vault output format; pick one from #{formats.map(&:to_s)}") do |f|
      options[:format] = f
    end
    opts.on('-e', '--except x,y,z', Array,
            'Specify fields to hide; for example, `-e order.position,icon.iconCollection.id`') do |e|
      options[:except] = e
    end
    opts.on_tail('-h', '--help', 'Show this message') do
      puts opts
      exit 0
    end
  end

  begin
    parser.parse! ARGV
    raise StandardError, "invalid number of arguments: expected 1, got #{ARGV.length}" if ARGV.length != 1

    if options[:format] == :json && !options[:except].empty?
      raise StandardError,
            'hiding fields is only supported for `csv` and `pretty` formats'
    end
  rescue StandardError => e
    terminate "#{e}\n#{parser}"
  end

  plain_text = decrypt_vault(ARGV[0])
  $stdout.write case options[:format]
                when :pretty
                  beautify remove_fields(entries_to_csv(plain_text), options[:except])
                when :csv
                  remove_fields(entries_to_csv(plain_text), options[:except])
                else
                  plain_text
                end
end

main if __FILE__ == $PROGRAM_NAME
