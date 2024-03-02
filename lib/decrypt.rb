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
require 'optparse'

require_relative 'crypto'
require_relative 'pretty'

AUTH_TAG_LENGTH = 16
SERVICES_ENCRYPTED_FIELD_LENGTH = 3

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
# Parse vault parameters from vault at `filename`.
#
# @param [String] filename Vault filename
#
# @return [Hash] Vault parameters
#
def parse_vault_params(filename)
  begin
    obj = parse_json File.read(filename, :encoding => 'utf-8')
  rescue Errno::ENOENT => e
    terminate e.to_s
  end
  cipher_text_with_auth_tag, salt, iv = extract_fields(obj).values_at(:cipher_text_with_auth_tag, :salt, :iv)
  cipher_text, auth_tag = split_cipher_text(cipher_text_with_auth_tag).values_at(:cipher_text, :auth_tag)
  { :cipher_text => cipher_text, :salt => salt, :iv => iv, :auth_tag => auth_tag }
end

def parse_args
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
  options
end

#
# Accept vault filename as a command-line argument, and optionally output format and fields to exclude.
# Decrypt the vault and write its contents to $stdout in specified output format.
#
# @param [String] filename Vault file to decrypt
# @param [String] format Output format (Default: json)
#
def main
  options = parse_args
  vault_params = parse_vault_params ARGV[0]
  vault_params[:password] = getpass('Enter 2FAS encrypted backup password: ')

  plain_text, = decrypt_ciphertext(vault_params[:cipher_text], vault_params[:password], vault_params[:salt],
                                   vault_params[:iv], vault_params[:auth_tag])
  parse_json(plain_text) # Ensure plain_text is valid JSON.

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
