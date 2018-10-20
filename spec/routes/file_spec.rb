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
require 'yaml'


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

  describe 'GET files' do
    context 'without (UU)ID given' do
      before do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        get '/files', nil, headers
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
    end
  end


  # Posts two different files
  describe 'POST /files' do
    context 'post arbitrary files' do
      $file_uuids = []
      filenames = [ 'samples/dependencies_mapping/MyExample',
                    'samples/dependencies_mapping/MyExample.cfg']
      filenames.each_with_index do |filename,idx|
        headers = { 'CONTENT_TYPE' => 'application/octet-stream',
                    'HTTP_CONTENT_DISPOSITION' => "attachment; filename=#{filename}" }
        it 'Submit two arbitrary files' do
          post '/files', File.binread(filename), headers
          $file_uuids[idx] = JSON.parse(last_response.body)
          p $file_uuids
          expect(last_response.status).to eq 201
        end
      end
    end
  end


  # Posts the above files with the same filenames and same content
  describe 'POST /files' do
    context 'post arbitrary files' do
      filenames = [ 'samples/dependencies_mapping/MyExample',
                    'samples/dependencies_mapping/MyExample.cfg']
      filenames.each_with_index do |filename, idx|
        headers = { 'CONTENT_TYPE' => 'application/octet-stream',
                    'HTTP_CONTENT_DISPOSITION' => "attachment; filename=#{filename}" }
        it 'Submit two files with same filename' do
          post '/files', File.binread(filename), headers
          expect(last_response.status).to eq 200
          expect(JSON.parse(last_response.body)).to include('uuid' => $file_uuids[idx]['uuid'].to_s)
        end
      end
    end
  end



  # Posts the above files with the different filenames but same content
  # Check of reuse and update counter
  describe 'POST /files' do
    $file_uuids_dup = []
    context 'post arbitrary files' do
      filenames = [ 'samples/dependencies_mapping/MyExample_dup',
                    'samples/dependencies_mapping/MyExample_dup.cfg']
      filenames.each_with_index do |filename, idx|
        headers = { 'CONTENT_TYPE' => 'application/octet-stream',
                    'HTTP_CONTENT_DISPOSITION' => "attachment; filename=#{filename}"}
        it 'Submit two files with same content' do
          post '/files', File.binread(filename), headers
          $file_uuids_dup[idx] = JSON.parse(last_response.body)
          puts $file_uuids_dup
          expect(last_response.status).to eq 200
        end
      end
    end
  end


  # Get the above upload files
  describe 'GET files' do
    context 'with uuid given' do
      $file_uuids.each do |uuid|
        headers = { 'CONTENT_TYPE' => 'application/json' }
        it 'Submit two files' do
          get '/files?' + uuid['uuid'], nil, headers
          expect(last_response.status).to eq 200
          # expect(JSON.parse(last_response.body)).to include('pkg_ref' => '2')
        end
      end
    end
  end



  # Posts the above files with the same filenames and same content
  #
  describe 'POST /files' do
    context 'post arbitrary files' do
      filenames = [ 'samples/dependencies_mapping/MyExample',
                    'samples/dependencies_mapping/MyExample.cfg']
      filenames.each_with_index do |filename, idx|
        headers = { 'CONTENT_TYPE' => 'application/octet-stream',
                    'HTTP_CONTENT_DISPOSITION' => "attachment; filename=#{filename}" }
        it 'Submit two files with same filename' do
          post '/files', File.binread(filename), headers
          expect(last_response.status).to eq 200
          expect(JSON.parse(last_response.body)).to include('uuid' => $file_uuids[idx]['uuid'].to_s)
        end
      end
    end
  end



  describe 'GET /api/v2/files/:uuid' do
    context 'with uuid given' do
      before do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        get '/files/' + $file_uuids_dup[0]['uuid'].to_s, nil, headers
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
      its(:body){ is_expected.to include 'md5',$file_uuids[0]['md5'].to_s }
    end
  end

  describe 'GET /api/v2/files/:uuid' do
    context 'with uuid given' do
      before do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        get '/files/' + $file_uuids_dup[1]['uuid'].to_s, nil, headers
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
      its(:body){ is_expected.to include 'md5',$file_uuids[1]['md5'].to_s }
    end
  end



  # Delete the first above upload files.
  # Since reuse is used,
  describe 'DELETE /api/v2/files/:uuid' do
    context 'with uuid given' do
      before do
        delete '/files/' + $file_uuids[0]['uuid'].to_s
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
      its(:body) { is_expected.to include 'referenced','1'}

    end
  end
  # Delete the first above upload files.
  # Since reuse is used,
  describe 'DELETE /api/v2/files/:uuid' do
    context 'with uuid given' do
      before do
        delete '/files/' + $file_uuids[0]['uuid'].to_s
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
      # its(:body) { is_expected.to include 'referenced','1'}

    end
  end

  # Delete the first above upload files.
  # Since reuse is used,
  describe 'DELETE /api/v2/files/:uuid' do
    context 'with uuid given' do
      before do
        delete '/files/' + $file_uuids[1]['uuid'].to_s
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
      its(:body) { is_expected.to include 'referenced','1'}

    end
  end

  # Delete the first above upload files.
  # Since reuse is used,
  describe 'DELETE /api/v2/files/:uuid' do
    context 'with uuid given' do
      before do
        delete '/files/' + $file_uuids[1]['uuid'].to_s
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
      # its(:body) { is_expected.to include 'referenced','1'}

    end
  end

  # # Delete the first above upload files.
  # # Since reuse is used,
  # describe 'DELETE /api/v2/files/:uuid' do
  #   context 'with uuid given' do
  #     before do
  #       delete '/files/' + $file_uuids[0]['uuid'].to_s
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 200 }
  #     # its(:body) { is_expected.to include 'OK: File removed'}
  #
  #   end
  # end

  # # Delete the first above upload files.
  # # Since reuse is used,
  # describe 'DELETE /api/v2/files/:uuid' do
  #   context 'with uuid given' do
  #     before do
  #       delete '/files/' + $file_uuids[1]['uuid'].to_s
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 200 }
  #     its(:body) { is_expected.to include 'OK: File removed'}
  #
  #   end
  # end
  #
  # # Delete the first above upload files.
  # # Since reuse is used,
  # describe 'DELETE /api/v2/files/:uuid' do
  #   context 'with uuid given' do
  #     before do
  #       delete '/files/' + $file_uuids_dup[0]['uuid'].to_s
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 200 }
  #     its(:body) { is_expected.to include 'OK: File removed'}
  #
  #   end
  # end

  # Delete the first above upload files.
  # Since reuse is used,
  describe 'DELETE /api/v2/files/:uuid' do
    context 'with uuid given' do
      before do
        delete '/files/' + $file_uuids_dup[1]['uuid'].to_s
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
      # its(:body) { is_expected.to include 'OK: File removed'}

    end
  end

  describe 'DELETE /api/v2/files/:uuid' do
    context 'with uuid given' do
      before do
        delete '/files/' + $file_uuids_dup[0]['uuid'].to_s
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
      # its(:body) { is_expected.to include 'OK: File removed'}

    end
  end

  # # Deletes the second package posted
  # describe 'DELETE /api/v2/packages' do
  #   context 'deleting pds' do
  #     before do
  #       puts 'Deleting sonata-demo-2.son'
  #       delete_response = delete '/packages/' + $pd_uuids[1]
  #       puts delete_response.body
  #       puts
  #       expect(delete_response.status).to eq(200)
  #       result = JSON.parse(delete_response.body)
  #       expect(result['result']['delete']['vnfds'].length).to eq(1)
  #       # tcpdump-vnf, sonata-demo-2.son was deleted so tcpdump-vnf can be deleted
  #       expect(result['result']['delete']['vnfds'][0]['name']).to eq('tcpdump-vnf')
  #       expect(result['result']['cant_delete']['nsds'].length).to eq(1)
  #       # NSD sonata-demo-2 required in package sonata-demo-3.son
  #       expect(result['result']['cant_delete']['nsds'][0]['name']).to eq('sonata-demo-2')
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 200 }
  #   end
  # end
  # # Tries to disable first package posted in previous test resulting
  # #    in the deletion of
  # #    {"disabled":
  # #    {"vnfds":[{"vendor":"eu.sonata-nfv","version":"0.3","name":"firewall-vnf"},
  # #    {"vendor":"eu.sonata-nfv","version":"0.2","name":"iperf-vnf"}],
  # #    "nsds":[{"vendor":"eu.sonata-nfv.service-descriptor","version":"0.2.1","name":"sonata-demo"}]}}
  # # But preventing tcpdump-vnfd disable because second package posted before has a dependency on it
  # describe 'PUT /api/v2/packages' do
  #   context 'disabling pds' do
  #     before do
  #       puts 'Disabling sonata-demo.son'
  #       disable_response = put '/packages/' + $pd_uuids[0] + '/status',
  #                          '{ "status": "inactive" }',
  #                          { 'CONTENT_TYPE' => 'application/json' }
  #       puts disable_response.body
  #       puts
  #       expect(disable_response.status).to eq(200)
  #       result = JSON.parse(disable_response.body)
  #       expect(result['result']['disable']['vnfds'].length).to eq(1)
  #       # Since the only VNF in sonata-demo.son not included in sonata-demo-2.son
  #       #    and sonata-demo-3.son is iperf-vnf
  #       expect(result['result']['disable']['vnfds'][0]['name']).to eq('iperf-vnf')
  #       expect(result['result']['disable']['nsds'].length).to eq(1)
  #       expect(result['result']['disable']['nsds'][0]['name']).to eq('sonata-demo')
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 200 }
  #   end
  # end
  #
  # # Tries to disable second package posted in previous test resulting
  # describe 'PUT /api/v2/packages' do
  #   context 'disabling pds' do
  #     before do
  #       puts 'Disabling sonata-demo-2.son'
  #       disable_response = put '/packages/' + $pd_uuids[1] + '/status',
  #                          '{ "status": "inactive" }',
  #                          { 'CONTENT_TYPE' => 'application/json' }
  #       puts disable_response.body
  #       puts
  #       expect(disable_response.status).to eq(200)
  #       result = JSON.parse(disable_response.body)
  #       expect(result['result']['disable']['vnfds'].length).to eq(1)
  #       # Since sonata-demo.son is disabled, tcpdump-vnf can now be safely disabled
  #       #    when disabling sonata-demo-2.son
  #       expect(result['result']['disable']['vnfds'][0]['name']).to eq('tcpdump-vnf')
  #       expect(result['result']['disable']['nsds'].length).to eq(0)
  #       expect(result['result']['cant_disable']['nsds'].length).to eq(1)
  #       # Since sonata-demo-3.son depends on sonata-demo-2 it can't be disabled
  #       expect(result['result']['cant_disable']['nsds'][0]['name']).to eq('sonata-demo-2')
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 200 }
  #   end
  # end
  #
  # # Tries to enable second package posted in previous test resulting
  # describe 'PUT /api/v2/packages' do
  #   context 'enabling pds' do
  #     before do
  #       puts 'Enabling sonata-demo-2.son'
  #       enable_response = put '/packages/' + $pd_uuids[1] + '/status',
  #                          '{ "status": "active" }',
  #                          { 'CONTENT_TYPE' => 'application/json' }
  #       puts enable_response.body
  #       puts
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 200 }
  #   end
  # end

  # # Tries to delete first package posted in previous test resulting
  # #    in the deletion of
  # #    {"deleted":
  # #    {"vnfds":[{"vendor":"eu.sonata-nfv","version":"0.3","name":"firewall-vnf"},
  # #    {"vendor":"eu.sonata-nfv","version":"0.2","name":"iperf-vnf"}],
  # #    "nsds":[{"vendor":"eu.sonata-nfv.service-descriptor","version":"0.2.1","name":"sonata-demo"}]}}
  # # But preventing tcpdump-vnf and firewall-vnf deletion because second package posted before has a dependency on it
  # describe 'DELETE /api/v2/packages' do
  #   context 'deleting pds' do
  #     before do
  #       puts 'Deleting sonata-demo.son'
  #       delete_response = delete '/packages/' + $pd_uuids[0]
  #       puts delete_response.body
  #       puts
  #       expect(delete_response.status).to eq(200)
  #       result = JSON.parse(delete_response.body)
  #       expect(result['result']['delete']['vnfds'].length).to eq(1)
  #       expect(result['result']['delete']['vnfds'][0]['name']).to eq('iperf-vnf')
  #       expect(result['result']['delete']['nsds'].length).to eq(1)
  #       expect(result['result']['delete']['nsds'][0]['name']).to eq('sonata-demo')
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 200 }
  #   end
  # end
  #
  # # Deletes the second package posted
  # describe 'DELETE /api/v2/packages' do
  #   context 'deleting pds' do
  #     before do
  #       puts 'Deleting sonata-demo-2.son'
  #       delete_response = delete '/packages/' + $pd_uuids[1]
  #       puts delete_response.body
  #       puts
  #       expect(delete_response.status).to eq(200)
  #       result = JSON.parse(delete_response.body)
  #       expect(result['result']['delete']['vnfds'].length).to eq(1)
  #       # tcpdump-vnf, sonata-demo-2.son was deleted so tcpdump-vnf can be deleted
  #       expect(result['result']['delete']['vnfds'][0]['name']).to eq('tcpdump-vnf')
  #       expect(result['result']['cant_delete']['nsds'].length).to eq(1)
  #       # NSD sonata-demo-2 required in package sonata-demo-3.son
  #       expect(result['result']['cant_delete']['nsds'][0]['name']).to eq('sonata-demo-2')
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 200 }
  #   end
  # end
  #
  # # Deletes the third package posted
  # describe 'DELETE /api/v2/packages' do
  #   context 'deleting pds' do
  #     before do
  #       puts 'Deleting sonata-demo-3.son'
  #       delete_response = delete '/packages/' + $pd_uuids[2]
  #       puts delete_response.body
  #       puts
  #       expect(delete_response.status).to eq(200)
  #       result = JSON.parse(delete_response.body)
  #       expect(result['result']['delete']['vnfds'].length).to eq(1)
  #       expect(result['result']['delete']['vnfds'][0]['name']).to eq('firewall-vnf')
  #       expect(result['result']['delete']['nsds'].length).to eq(1)
  #       expect(result['result']['delete']['nsds'][0]['name']).to eq('sonata-demo-2')
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 200 }
  #   end
  # end


  # # Posts the same above files
  # describe 'POST /files' do
  #   context 'post arbitrary files' do
  #     before do
  #       filenames = [ 'samples/dependencies_mapping/MyExample_dup',
  #                     'samples/dependencies_mapping/MyExample_dup.cfg']
  #       filenames.each do |filename|
  #         headers = { 'CONTENT_TYPE' => 'application/octet-stream',
  #                     'HTTP_CONTENT_DISPOSITION' => "attachment; filename=#{filename}" }
  #         response = post '/files', File.binread(filename), headers
  #       end
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 200 }
  #     its(:body) { is_expected.to include 'Referenced => 2' }
  #   end
  # end
  #
  # # Posts the same above files
  # describe 'POST /files' do
  #   context 'post arbitrary files' do
  #     before do
  #       filenames = [ 'samples/dependencies_mapping/MyExample',
  #                     'samples/dependencies_mapping/MyExample.cfg']
  #       filenames.each do |filename|
  #         headers = { 'CONTENT_TYPE' => 'application/octet-stream',
  #                     'HTTP_CONTENT_DISPOSITION' => "attachment; filename=#{filename}" }
  #         response = post '/files', File.binread(filename), headers
  #       end
  #     end
  #     subject { last_response }
  #     its(:status) { is_expected.to eq 409 }
  #     its(:body) { is_expected.to include 'samples/dependencies_mapping/MyExample.cfg' }
  #   end
  # end
end
