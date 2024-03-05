# 2FAS Backup Decryptor

[![Ruby](https://img.shields.io/badge/Ruby-CC342D?style=for-the-badge&logo=ruby&logoColor=white)](https://ruby-lang.org)
[![Coveralls](https://img.shields.io/coverallsCoverage/github/elliotwutingfeng/2fas-backup-decryptor?logo=coveralls&style=for-the-badge)](https://coveralls.io/github/elliotwutingfeng/2fas-backup-decryptor?branch=main)
[![GitHub license](https://img.shields.io/badge/LICENSE-GPLv3-GREEN?style=for-the-badge)](LICENSE)

CLI tool to decrypt backup files exported from the [2FAS Authenticator app](https://2fas.com).

This application is neither affiliated with Two Factor Authentication Service, Inc. nor 2FAS.

## Requirements

- **Ruby:** 2.0+/3.0+, no external gems needed
- **OS:** Either Windows, macOS, or Linux

## Example

**File:** `test/encrypted_test.2fas`

**Password:** `example.com`

```bash
# Enter the above password when prompted
ruby lib/decrypt.rb test/encrypted_test.2fas
```

You should get the following plaintext JSON output.

```json
[{"name":"Deno","secret":"4SJHB4GSD43FZBAI7C2HLRJGPQ","updatedAt":1708958115316,"otp":{"label":"Mason","account":"Mason","issuer":"Deno","digits":6,"period":30,"algorithm":"SHA1","tokenType":"TOTP","source":"Link"},"order":{"position":0},"icon":{"selected":"Label","label":{"text":"DE","backgroundColor":"Brown"},"iconCollection":{"id":"a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad"}}},{"name":"SPDX","secret":"5OM4WOOGPLQEF6UGN3CPEOOLWU","updatedAt":1708958115348,"otp":{"label":"James","account":"James","issuer":"SPDX","digits":7,"period":30,"algorithm":"SHA256","tokenType":"TOTP","source":"Link"},"order":{"position":1},"icon":{"selected":"Label","label":{"text":"SP","backgroundColor":"Red"},"iconCollection":{"id":"a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad"}}},{"name":"Airbnb","secret":"7ELGJSGXNCCTV3O6LKJWYFV2RA","updatedAt":1708958115376,"otp":{"label":"Elijah","account":"Elijah","issuer":"Airbnb","digits":8,"period":60,"algorithm":"SHA512","tokenType":"TOTP","source":"Link"},"order":{"position":2},"icon":{"selected":"Label","label":{"text":"AI","backgroundColor":"Pink"},"iconCollection":{"id":"a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad"}}},{"name":"Boeing","secret":"JRZCL47CMXVOQMNPZR2F7J4RGI","updatedAt":1708958115391,"otp":{"label":"Sophia","account":"Sophia","issuer":"Boeing","digits":5,"period":10,"algorithm":"SHA1","tokenType":"STEAM","source":"Link"},"order":{"position":3},"icon":{"selected":"Label","label":{"text":"BO","backgroundColor":"Brown"},"iconCollection":{"id":"a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad"}}},{"name":"Air Canada","secret":"KUVJJOM753IHTNDSZVCNKL7GII","updatedAt":1708958401763,"otp":{"link":"otpauth://hotp/Benjamin?secret=KUVJJOM753IHTNDSZVCNKL7GII&issuer=Air%20Canada&counter=10&algorithm=SHA256&digits=8","label":"Benjamin","account":"Benjamin","issuer":"Air Canada","digits":8,"algorithm":"SHA256","counter":10,"tokenType":"HOTP","source":"Link"},"order":{"position":4},"icon":{"selected":"Label","label":{"text":"AI","backgroundColor":"Brown"},"iconCollection":{"id":"a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad"}}}]
```

### Other formats

You can also add the `-f / --format` option to print the plaintext output as `csv` or as a `pretty` CSV-like String padded with spaces.

#### csv

```bash
# Enter the above password when prompted
ruby lib/decrypt.rb test/encrypted_test.2fas -f csv
```

```csv
icon.iconCollection.id,icon.label.backgroundColor,icon.label.text,icon.selected,name,order.position,otp.account,otp.algorithm,otp.counter,otp.digits,otp.issuer,otp.label,otp.link,otp.period,otp.source,otp.tokenType,secret,updatedAt
a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad,Brown,DE,Label,Deno,0,Mason,SHA1,,6,Deno,Mason,,30,Link,TOTP,4SJHB4GSD43FZBAI7C2HLRJGPQ,1708958115316
a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad,Red,SP,Label,SPDX,1,James,SHA256,,7,SPDX,James,,30,Link,TOTP,5OM4WOOGPLQEF6UGN3CPEOOLWU,1708958115348
a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad,Pink,AI,Label,Airbnb,2,Elijah,SHA512,,8,Airbnb,Elijah,,60,Link,TOTP,7ELGJSGXNCCTV3O6LKJWYFV2RA,1708958115376
a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad,Brown,BO,Label,Boeing,3,Sophia,SHA1,,5,Boeing,Sophia,,10,Link,STEAM,JRZCL47CMXVOQMNPZR2F7J4RGI,1708958115391
a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad,Brown,AI,Label,Air Canada,4,Benjamin,SHA256,10,8,Air Canada,Benjamin,otpauth://hotp/Benjamin?secret=KUVJJOM753IHTNDSZVCNKL7GII&issuer=Air%20Canada&counter=10&algorithm=SHA256&digits=8,,Link,HOTP,KUVJJOM753IHTNDSZVCNKL7GII,1708958401763
```

#### pretty

```bash
# Enter the above password when prompted
ruby lib/decrypt.rb test/encrypted_test.2fas -f pretty
```

```csv
icon.iconCollection.id                icon.label.backgroundColor  icon.label.text  icon.selected  name        order.position  otp.account  otp.algorithm  otp.counter  otp.digits  otp.issuer  otp.label  otp.link                                                                                                            otp.period  otp.source  otp.tokenType  secret                      updatedAt
a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad  Brown                       DE               Label          Deno        0               Mason        SHA1                        6           Deno        Mason                                                                                                                          30          Link        TOTP           4SJHB4GSD43FZBAI7C2HLRJGPQ  1708958115316
a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad  Red                         SP               Label          SPDX        1               James        SHA256                      7           SPDX        James                                                                                                                          30          Link        TOTP           5OM4WOOGPLQEF6UGN3CPEOOLWU  1708958115348
a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad  Pink                        AI               Label          Airbnb      2               Elijah       SHA512                      8           Airbnb      Elijah                                                                                                                         60          Link        TOTP           7ELGJSGXNCCTV3O6LKJWYFV2RA  1708958115376
a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad  Brown                       BO               Label          Boeing      3               Sophia       SHA1                        5           Boeing      Sophia                                                                                                                         10          Link        STEAM          JRZCL47CMXVOQMNPZR2F7J4RGI  1708958115391
a5b3fb65-4ec5-43e6-8ec1-49e24ca9e7ad  Brown                       AI               Label          Air Canada  4               Benjamin     SHA256         10           8           Air Canada  Benjamin   otpauth://hotp/Benjamin?secret=KUVJJOM753IHTNDSZVCNKL7GII&issuer=Air%20Canada&counter=10&algorithm=SHA256&digits=8              Link        HOTP           KUVJJOM753IHTNDSZVCNKL7GII  1708958401763
```

### Hiding unwanted fields

When the `-f / --format` option is set to `csv` or `pretty`, you can use the `-e / --except` option to hide unwanted fields. Non-existent fields are silently ignored.

```bash
# Enter the above password when prompted
ruby lib/decrypt.rb test/encrypted_test.2fas -f pretty -e icon.iconCollection.id,icon.label.backgroundColor,icon.label.text,icon.selected,order.position,otp.link,name,otp.account,otp.source,updatedAt,otp.counter
```

```csv
otp.algorithm  otp.digits  otp.issuer  otp.label  otp.period  otp.tokenType  secret
SHA1           6           Deno        Mason      30          TOTP           4SJHB4GSD43FZBAI7C2HLRJGPQ
SHA256         7           SPDX        James      30          TOTP           5OM4WOOGPLQEF6UGN3CPEOOLWU
SHA512         8           Airbnb      Elijah     60          TOTP           7ELGJSGXNCCTV3O6LKJWYFV2RA
SHA1           5           Boeing      Sophia     10          STEAM          JRZCL47CMXVOQMNPZR2F7J4RGI
SHA256         8           Air Canada  Benjamin               HOTP           KUVJJOM753IHTNDSZVCNKL7GII
```

## Testing

```bash
# The test suite requires Ruby 2.4 or newer
gem install bundler
bundle install
bundle exec rspec -r spec_helper
```
