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
# located at the `:servicesEncrypted` key of JSON Hash `obj`
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
# Separate cipher text from 16-byte AES-GCM authentication tag
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
# Decrypt `cipher_text` and return the plaintext result as String
#
# @param [String] cipher_text Encrypted text as bytes to be decrypted
# @param [String] password Backup file password as plaintext
# @param [String] salt HMAC salt as bytes
# @param [String] iv AES-GCM initialization vector as bytes
# @param [String] auth_tag AES-GCM authentication tag as bytes
#
# @return [String] Decrypted `cipher_text`
#
def decrypt_ciphertext(cipher_text, password, salt, iv, auth_tag)
  decipher = OpenSSL::Cipher.new ENCRYPTION_CIPHER
  decipher.decrypt
  decipher.key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, ITERATIONS, KEY_LENGTH / 8,
                                            HASH)
  decipher.iv = iv
  decipher.auth_tag = auth_tag
  decipher.auth_data = ''
  decipher.padding = 0

  begin
    decipher.update(cipher_text) + decipher.final
  rescue OpenSSL::Cipher::CipherError
    terminate 'Failed to derive cipher key. Wrong password?'
  end
end

def encrypt_ciphertext(plain_text, password, salt, iv)
  encipher = OpenSSL::Cipher.new ENCRYPTION_CIPHER
  encipher.encrypt
  encipher.key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, ITERATIONS, KEY_LENGTH / 8,
                                            HASH)
  encipher.iv = iv
  encipher.auth_data = ''
  encipher.padding = 0

  begin
    encrypted = encipher.update(plain_text) + encipher.final
    auth_tag = encipher.auth_tag
  rescue OpenSSL::Cipher::CipherError
    terminate 'Failed to encrypt plaintext. Wrong parameters?'
  end
  Base64.strict_encode64(encrypted + auth_tag)
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
  plain_text = decrypt_ciphertext(cipher_text, password, salt, iv, auth_tag)
  parse_json(plain_text) # Ensure plain_text is valid JSON.
  plain_text
end

def encrypt_vault(plain_text, password, salt, iv)
  cipher_text_with_auth_tag = encrypt_ciphertext(plain_text, password, Base64.strict_decode64(salt),
                                                 Base64.strict_decode64(iv))
  '{"services":[],"groups":[],"updatedAt":1708958781890,"schemaVersion":4,"appVersionCode":5000017,' \
    '"appVersionName":"5.3.5","appOrigin":"android","servicesEncrypted":' \
    "\"#{cipher_text_with_auth_tag}:#{salt}:#{iv}\"," \
    '"reference":"lPyg4X0eUVHys/yulzNkR2lVONpCe5KK883sl+ir6B6bYbu2+69nN0bUDI9B9X53DKs3/54JqYRhYrI0a6It9SWR9NHJc1jsAXg0G8tqVOcQdcf4rdhYIg5VJh77h5wSTqt70aH6kfo9IhiTEfRFSDScny0qH1YxzqlDQm3Uw1jHdwW6UFFAA+3/uSTmcD4aoeknWbXP8GwH4z/ORM9VmonyX85LY4tszMjeTeb2U/hjxVaMluJYCn8VFzGsZqec3ayt8E7cHTusGy0tr+gGtM7Fm/iBYUwAUCaOS9XZQhyB3tJq2gNp5ajsS6zEJsKhWXyNU/f0ircshOUGRLm1eCSAiexGT/3/avGkoZMExqY=:xsCM/GAwNcyqrDcYodp58e6xxXl+cj0P+1Bh9mH4f7+UYKrQV4cpMAbQRPyNJz5CbsvSsFGYr+Ls1N+GyX6fp8LahIyovloySTRqQZzBI0VgKTKy1g7PlSSVjhedokyK5osUg6lUTimr29SGyvL4r/ornfkKygDZry8gHjyANX06mfxBK46+qomjsw5TErS0VlitPMJ1OWoh5/ZArEZBSczTGSOLjdQ3uMkQGOEUCJAd9wruBViN7td/0tmBAhzkG7EtrOJN7YNCGSLCiRoeLqS+unbaIOmUeKyn2AWd+jT/k4WcxIkHlYPRumy1DzS/REh6NUfagoO/1fPLMUYUug==:Jz6KfVsBSV9u04o2"}'
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
