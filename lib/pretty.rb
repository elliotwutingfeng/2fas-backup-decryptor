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

require 'csv'
require 'json'

def terminate(message)
  warn message
  exit 1
end

#
# Parse `plain_text` string as JSON object
#
# @param [String] plain_text Encoded JSON string
#
# @return [BasicObject] JSON object
#
def parse_json(plain_text)
  JSON.parse(plain_text, :symbolize_names => true)
rescue JSON::ParserError
  terminate 'Failed to parse JSON file. Invalid JSON?'
end

#
# Recursively flatten a nested JSON object into a single-level hash.
#
# @param [Hash] json_data JSON object to be flattened
# @param [String] parent_key Parent key for the current level
#
# @return [Hash] Flattened JSON data where keys are concatenated
#  with dots to represent nested structure
#
def flatten_json(json_data, parent_key)
  json_data.each_with_object({}) do |(key, value), hash|
    new_key = parent_key.empty? ? key.to_sym : :"#{parent_key}.#{key}"
    if value.is_a?(Hash)
      hash.merge!(flatten_json(value, new_key))
    else
      hash[new_key] = value.is_a?(Array) ? value.to_json : value # Do not unpack arrays.
    end
  end
end

#
# Convert JSON array String plain_text to CSV String.
#
# @param [String] plain_text JSON String
#
# @return [String] CSV String
#
def entries_to_csv(plain_text)
  flattened_data = parse_json(plain_text).map { |record| flatten_json(record, '') }
  # In context of this application, the vault data looks more readable in ascending alphabetical order.
  headers = flattened_data.flat_map(&:keys).uniq.sort { |a, b| a <=> b }

  CSV.generate do |csv|
    csv << headers
    flattened_data.each do |record|
      csv << headers.map { |header| record[header] }
    end
  end
end

#
# Remove specified fields from a CSV string. Non-existent fields are silently ignored.
#
# @param [String] raw_csv CSV String
# @param [Array<String>] fields_to_remove Field names to be removed from the CSV String
#
# @return [String] CSV String with specified fields removed
#
def remove_fields(raw_csv, fields_to_remove)
  csv_data = CSV.parse(raw_csv, :headers => true)
  fields_to_remove.each do |field_name|
    csv_data.delete field_name
  end
  csv_data.to_s
end

#
# Make a beautiful CSV-like String padded with spaces.
#
# @param [String] raw_csv CSV String
#
# @return [String] Beautiful CSV-like String padded with spaces
#
def beautify(raw_csv)
  csv_data = CSV.parse(raw_csv)
  column_widths = Array.new(csv_data.first.length, 0) # Calculate column widths.
  csv_data.each do |row|
    row.each_with_index do |cell, index|
      column_widths[index] = [column_widths[index], cell.to_s.length].max
    end
  end

  output = '' # Pretty print CSV with justified columns.
  csv_data.each do |row|
    row.each_with_index do |cell, index|
      output << cell.to_s.ljust(column_widths[index] + 2) # Pad with 2 spaces.
    end
    output.rstrip!
    output << "\n"
  end
  output
end
