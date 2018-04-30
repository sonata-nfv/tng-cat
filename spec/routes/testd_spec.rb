## Copyright (c) 2015 SONATA-NFV, 2017 5GTANGO [, ANY ADDITIONAL AFFILIATION]
## ALL RIGHTS RESERVED.
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##
## Neither the name of the SONATA-NFV, 5GTANGO [, ANY ADDITIONAL AFFILIATION]
## nor the names of its contributors may be used to endorse or promote
## products derived from this software without specific prior written
## permission.
##
## This work has been performed in the framework of the SONATA project,
## funded by the European Commission under Grant number 671517 through
## the Horizon 2020 and 5G-PPP programmes. The authors would like to
## acknowledge the contributions of their colleagues of the SONATA
## partner consortium (www.sonata-nfv.eu).
##
## This work has been performed in the framework of the 5GTANGO project,
## funded by the European Commission under Grant number 761493 through
## the Horizon 2020 and 5G-PPP programmes. The authors would like to
## acknowledge the contributions of their colleagues of the 5GTANGO
## partner consortium (www.5gtango.eu).
require_relative '../spec_helper'
require 'webmock/rspec'
require 'json'
require 'securerandom'
require 'pp'
require 'rspec/its'


RSpec.describe CatalogueV2 do

  def app
    @app ||= CatalogueV2
  end

  describe 'GET \'/\'' do
    before do
      stub_request(:get, 'localhost:5000').to_return(status: 200)
      get '/'
    end
    subject { last_response }
    its(:status) { is_expected.to eq 200 }
  end

  let(:test_descriptor) {Rack::Test::UploadedFile.new('./spec/fixtures/testd-example.json','application/json', true)}
  describe 'POST \'/api/v2/tests\'' do
    context 'with correct parameters' do
      it 'Submit a testd' do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        post '/tests', test_descriptor, headers
        expect(last_response.status).to eq(201)
        testd_body = JSON.parse(last_response.body)
        $testd_id = (testd_body['uuid'])
        $testd_name = (testd_body['name'])
      end
    end
  end

  let(:test_descriptor) {Rack::Test::UploadedFile.new('./spec/fixtures/testd-example.json','application/json', true)}
  describe 'POST \'/api/v2/tests\'' do
    context 'Duplicated testd' do
      it 'Submit a duplicated testd' do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        post '/tests', test_descriptor, headers
        expect(last_response.status).to eq(409)
      end
    end
  end

  let(:test_bad_descriptor) {Rack::Test::UploadedFile.new('./spec/fixtures/testd-example-with-errors.json',
                                                         'application/json', true)}
  describe 'POST \'/api/v2/tests-bad\'' do
    context 'with incorrect parameters' do
      it 'Submit an invalid testd' do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        post '/tests', test_bad_descriptor, headers
        expect(last_response.status).to eq(400)
      end
    end
  end

  describe 'GET /api/v2/tests' do
    context 'without (UU)ID given' do
      before do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        get '/tests', nil, headers
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
    end
  end

  describe 'GET /api/v2/tests' do
    context 'with name parameter given' do
      before do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        get '/tests?' + $testd_name.to_s, nil, headers
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
    end
  end

  describe 'GET /api/v2/tests/' do
    context 'with test_tag parameter given' do
      before do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        get '/tests?test_tag=io_bandwidth', nil,  headers
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
    end
  end

  describe 'GET /api/v2/tests/:uuid' do
    context 'with (UU)ID given' do
      before do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        get '/tests/' + $testd_id.to_s, nil, headers
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
    end
  end

  describe 'PUT /api/v2/tests/:uuid' do
    context 'update status to (UU)ID given' do
      before do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        put '/tests/' + $testd_id.to_s + '?status=inactive', nil, headers
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
    end
  end

  describe 'DELETE /api/v2/tests/:uuid' do
    context 'with (UU)ID given' do
      before do
        delete '/tests/' + $testd_id.to_s
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
    end
  end
end
