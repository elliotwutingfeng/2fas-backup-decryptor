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
require 'spec_helper'
require 'pretty'

describe 'parse_json' do
  it 'Parses valid JSON' do
    expect(parse_json('{"a": [1, 2]}')).to eq({ :a => [1, 2] })
  end
  it 'Exit 1 if invalid JSON' do
    silence do
      expect { parse_json('') }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
    end
  end
end

describe 'remove_fields' do
  it 'Removes fields from CSV String correctly' do
    expect(CSV.parse(remove_fields("a,b,c\n1,2,3", %w[a c]), :headers => true).headers).to eq ['b']
  end
end

describe 'beautify' do
  it 'Pretty prints plain text vault as a CSV-like String padded with spaces' do
    expect(beautify(entries_to_csv(File.read('test/plaintext_test.json',
                                             :encoding => 'utf-8')))).to eq File.read('test/pretty_test.txt',
                                                                                      :encoding => 'utf-8')
  end
end

balanced_json_data = [
  {
    :string1 => 'a_1',
    :nil1 => nil,
    :object1 => {
      :innerstring1 => 'a_1_1',
      :innerstring2 => 'a_1_2',
      :innerint1 => 6
    }
  },
  {
    :string1 => 'b_1',
    :nil1 => nil,
    :object1 => {
      :innerstring1 => 'b_1_1',
      :innerstring2 => 'b_1_2',
      :innerint1 => 6
    }
  }
]

# Unbalanced JSON is JSON array where an element has fields that subsequent elements do not and vice versa
unbalanced_json_data = [
  {
    :string1 => 'a_1',
    :string3 => 'a_3',
    :nil1 => nil,
    :object1 => {
      :innerstring1 => 'a_1_1',
      :innerstring2 => 'a_1_2',
      :innerint1 => 0xa
    }
  },
  {
    :string1 => 'b_1',
    :string2 => 'b_2',
    :nil1 => nil,
    :nil2 => nil,
    :object1 => {
      :innerstring1 => 'b_1_1',
      :innerstring2 => 'b_1_2',
      :innerstring3 => 'b_1_3',
      :innerint1 => 0xb,
      :innerint2 => 0xbb
    }
  }
]

describe 'flatten_json' do
  it 'No op for empty Hash' do
    expect(flatten_json({}, '')).to eq({})
  end

  it 'Flattens array where all elements have the exact same fields' do
    flattened_data = balanced_json_data.map { |record| flatten_json(record, '') }
    expect(flattened_data).to eq [{ :nil1 => nil,
                                    :'object1.innerint1' => 6,
                                    :'object1.innerstring1' => 'a_1_1',
                                    :'object1.innerstring2' => 'a_1_2',
                                    :string1 => 'a_1' },
                                  { :nil1 => nil,
                                    :'object1.innerint1' => 6,
                                    :'object1.innerstring1' => 'b_1_1',
                                    :'object1.innerstring2' => 'b_1_2',
                                    :string1 => 'b_1' }]
  end

  it 'Flattens array where an element has fields that subsequent elements do not and vice versa' do
    flattened_data = unbalanced_json_data.map { |record| flatten_json(record, '') }
    expect(flattened_data).to eq [{ :nil1 => nil,
                                    :'object1.innerint1' => 0xa,
                                    :'object1.innerstring1' => 'a_1_1',
                                    :'object1.innerstring2' => 'a_1_2',
                                    :string1 => 'a_1', :string3 => 'a_3' },
                                  { :nil1 => nil,
                                    :nil2 => nil,
                                    :'object1.innerint1' => 0xb,
                                    :'object1.innerint2' => 0xbb,
                                    :'object1.innerstring1' => 'b_1_1',
                                    :'object1.innerstring2' => 'b_1_2',
                                    :'object1.innerstring3' => 'b_1_3',
                                    :string1 => 'b_1', :string2 => 'b_2' }]
  end
end

describe 'entries_to_csv' do
  it 'Flattens balanced JSON to csv correctly' do
    flattened_csv = entries_to_csv balanced_json_data.to_json(:encoding => 'utf-8')
    expect(flattened_csv).to eq "nil1,object1.innerint1,object1.innerstring1,object1.innerstring2,string1\n" \
                                ",6,a_1_1,a_1_2,a_1\n" \
                                ",6,b_1_1,b_1_2,b_1\n"
  end

  it 'Flattens unbalanced JSON to csv correctly' do
    flattened_csv = entries_to_csv unbalanced_json_data.to_json(:encoding => 'utf-8')
    expect(flattened_csv).to eq 'nil1,nil2,object1.innerint1,object1.innerint2,object1.innerstring1,' \
                                "object1.innerstring2,object1.innerstring3,string1,string2,string3\n" \
                                ",,10,,a_1_1,a_1_2,,a_1,,a_3\n" \
                                ",,11,187,b_1_1,b_1_2,b_1_3,b_1,b_2,\n"
  end
end
