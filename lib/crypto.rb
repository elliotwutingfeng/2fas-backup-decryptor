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

require 'openssl'

abort 'LibreSSL is not supported by this program.' if OpenSSL::OPENSSL_LIBRARY_VERSION.downcase.include? 'libressl'
abort 'PBKDF2 support is missing.' if defined?(OpenSSL::PKCS5).nil? || !OpenSSL::PKCS5.methods.include?(:pbkdf2_hmac)

ITERATIONS = 10_000
KEY_LENGTH = 256
HASH = 'sha256'.freeze
ENCRYPTION_CIPHER = 'aes-256-gcm'.freeze

#
# Derive a key from the given password and salt using PBKDF2-HMAC.
#
# @param [String] password HMAC password as plaintext
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
  encrypt ? cipher.encrypt : cipher.decrypt
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
# @param [String] cipher_text bytes to be decrypted
# @param [String] password HMAC password as plaintext
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
  abort "Failed to derive cipher key. #{e.instance_of?(ArgumentError) ? e.message : 'Wrong password?'}"
end

#
# Encrypt `plain_text` and return its ciphertext and authentication tag.
#
# @param [String] plain_text bytes to be encrypted
# @param [String] password HMAC password as plaintext
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
  abort "Failed to encrypt plaintext. #{e.instance_of?(ArgumentError) ? e.message : 'Invalid parameters?'}"
end
