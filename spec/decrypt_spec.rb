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
require 'decrypt'

ENCRYPTED_TEST_VAULT = 'test/encrypted_test.2fas'.freeze

# See https://michaelay.github.io/blog/2014/12/15/suppress-stdout-and-stderr-when-running-rspec
def silence(filter = '')
  @original_stderr = $stderr
  @original_stdout = $stdout
  $stderr = StringIO.new if filter != 'stdout'
  $stdout = StringIO.new if filter != 'stderr'

  yield

  $stderr = @original_stderr
  $stdout = @original_stdout
  @original_stderr = nil
  @original_stdout = nil
end

describe 'split_cipher_text' do
  it 'Exit 1 if cipher text with auth tag length is too short' do
    silence do
      expect { split_cipher_text('A' * AUTH_TAG_LENGTH) }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
    end
  end
end

describe 'extract_fields' do
  it 'Extracts fields if number of fields is valid' do
    extracted = extract_fields(JSON.parse('{"servicesEncrypted": "MQ==:Mg==:Mw=="}', :symbolize_names => true))
    expected = { :cipher_text_with_auth_tag => '1', :salt => '2', :iv => '3' }
    extracted.each do |k, v|
      expect(v).to eq(expected[k])
    end
  end
  it 'Exit 1 if number of fields is invalid' do
    test_vectors = ['[]', '{}', '{"servicesEncrypted": ""}',
                    '{"servicesEncrypted": "MQ=="}',
                    '{"servicesEncrypted": "MQ==:"}',
                    '{"servicesEncrypted": "MQ==:Mg=="}',
                    '{"servicesEncrypted": "MQ==:Mg==:Mw==:NA=="}'].map do |s|
                      JSON.parse(s, :symbolize_names => true)
                    end
    silence do
      test_vectors.each do |obj|
        expect { extract_fields(obj) }.to raise_error(SystemExit) do |error|
          expect(error.status).to eq(1)
        end
      end
    end
  end
end

def decryption_test(args, expected_plaintext_filename)
  ARGV.replace args
  allow($stdin).to receive(:noecho) { 'example.com' } # Backup file password
  output = nil
  expect($stdout).to receive(:write) { |arg| output = arg }
  silence('stderr') do
    main
  end
  expected_plaintext_vault = File.read(expected_plaintext_filename, :encoding => 'utf-8')
  expect(output).to eq expected_plaintext_vault
end

describe 'encrypt_vault' do
  it 'Encrypts vault correctly' do
    plain_text = File.read('test/plaintext_test.json', :encoding => 'utf-8')
    password = 'example.com'
    # salt = 'xsCM/GAwNcyqrDcYodp58e6xxXl+cj0P+1Bh9mH4f7+UYKrQV4cpMAbQRPyNJz5CbsvSsFGYr+Ls1N+GyX6fp8LahIyovloyS' \
    #        'TRqQZzBI0VgKTKy1g7PlSSVjhedokyK5osUg6lUTimr29SGyvL4r/ornfkKygDZry8gHjyANX06mfxBK46+qomjsw5TErS0Vlit' \
    #        'PMJ1OWoh5/ZArEZBSczTGSOLjdQ3uMkQGOEUCJAd9wruBViN7td/0tmBAhzkG7EtrOJN7YNCGSLCiRoeLqS+unbaIOmUeKyn2AWd+' \
    #        'jT/k4WcxIkHlYPRumy1DzS/REh6NUfagoO/1fPLMUYUug=='
    # iv = '5UW4AuvcvsEi0jYe'
    salt = Base64.strict_encode64 OpenSSL::Random.random_bytes 16
    iv = Base64.strict_encode64 OpenSSL::Random.random_bytes 12
    encrypted_vault = encrypt_vault(plain_text, password, salt, iv)

    # Now try to decrypt it again
    obj = parse_json encrypted_vault
    cipher_text_with_auth_tag, salt, iv = extract_fields(obj).values_at(:cipher_text_with_auth_tag, :salt, :iv)
    cipher_text, auth_tag = split_cipher_text(cipher_text_with_auth_tag).values_at(:cipher_text, :auth_tag)
    expect(decrypt_ciphertext(cipher_text, password, salt, iv, auth_tag)).to eq plain_text
  end
end

describe 'main' do
  it 'Correct password -> Decryption success' do
    ['-f', '--format'].each do |flag|
      decryption_test([ENCRYPTED_TEST_VAULT, flag, 'json'], 'test/plaintext_test.json')
      decryption_test([ENCRYPTED_TEST_VAULT, flag, 'csv'], 'test/csv_test.csv')
      decryption_test([ENCRYPTED_TEST_VAULT, flag, 'pretty'], 'test/pretty_test.txt')
    end
  end
  it 'Wrong password -> Decryption failure' do
    ARGV.replace [ENCRYPTED_TEST_VAULT]
    allow($stdin).to receive(:noecho) { '' }
    expect { main }.to raise_error(SystemExit) do |error|
      expect(error.status).to eq(1)
    end
  end
  it 'No such file or directory -> SystemExit' do
    ARGV.replace ["#{ENCRYPTED_TEST_VAULT}_that_does_not_exist"]
    allow($stdin).to receive(:noecho) { '' }
    silence do
      expect { main }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
    end
  end
  it 'Accepts exactly 1 argument' do
    test_vectors = [[], [ENCRYPTED_TEST_VAULT, 'another'], [ENCRYPTED_TEST_VAULT, 'yet another']]
    silence do
      test_vectors.each do |args|
        ARGV.replace args
        expect { main }.to raise_error(SystemExit) do |error|
          expect(error.status).to eq(1)
        end
      end
    end
  end
  it 'Terminates if `--format` is `json` and `--except` fields are included' do
    silence do
      ARGV.replace [ENCRYPTED_TEST_VAULT, '-f', 'json', '-e', 'field']
      expect { main }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
    end
  end
  it 'Shows help' do
    ARGV.replace ['--help']
    output = nil
    expect($stdout).to receive(:write) { |arg| output = arg }
    expect { main }.to raise_error(SystemExit) do |error|
      expect(error.status).to eq(0)
    end
    expect(output.start_with?('Usage')).to eq true
  end
end
