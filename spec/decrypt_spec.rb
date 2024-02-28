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
