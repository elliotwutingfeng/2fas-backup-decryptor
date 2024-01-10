# 2FAS Backup Decryptor

[![Ruby](https://img.shields.io/badge/Ruby-CC342D?style=for-the-badge&logo=ruby&logoColor=white)](https://ruby-lang.org)
[![Codecov Coverage](https://img.shields.io/codecov/c/github/elliotwutingfeng/2fas-backup-decryptor?color=bright-green&logo=codecov&style=for-the-badge&token=)](https://codecov.io/gh/elliotwutingfeng/2fas-backup-decryptor)
[![GitHub license](https://img.shields.io/badge/LICENSE-GPLv3-GREEN?style=for-the-badge)](LICENSE)

CLI tool to decrypt backup files exported from the [2FAS Authenticator app](https://2fas.com).

This application is neither affiliated with Two Factor Authentication Service, Inc. nor 2FAS.

## Requirements

Ruby 2 or 3. No external dependencies needed.

## Example

**File:** `test/encrypted_test.2fas`

**Password:** `example.com`

```bash
# Enter the above password when prompted
ruby lib/decrypt.rb test/encrypted_test.2fas
```

You should get the following plaintext output.

```json
[{"name":"example.com","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","updatedAt":1704874073731,"otp":{"label":"","account":"","digits":6,"period":30,"algorithm":"SHA1","tokenType":"TOTP","source":"Manual"},"order":{"position":0},"icon":{"selected":"Label","label":{"text":"EX","backgroundColor":"Orange"},"iconCollection":{"id":"a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad"}}}]
```

## Testing

```bash
gem install bundler
bundle install
bundle exec rspec
```
