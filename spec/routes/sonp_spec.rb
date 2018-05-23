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

RSpec.describe CatalogueV1 do

  def app
    @app ||= CatalogueV1
  end

  describe 'GET \'/\'' do
    before do
      stub_request(:get, 'localhost:5000').to_return(status: 200)
      get '/'
    end
    subject { last_response }
    its(:status) { is_expected.to eq 200 }
  end

  describe 'GET /son-packages' do
    context 'without (UU)ID given' do
      before do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        get '/son-packages', nil, headers
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
    end
  end
end

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

  describe 'GET tgo-packages' do
    context 'without (UU)ID given' do
      before do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        get '/tgo-packages', nil, headers
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
    end
  end

  # Posts two different sonata packages, first one contains as vnfds firewall-vnfd,
  #    iperf-vnfd and tcpdump-vnfd; second one contains only tcpdump-vnfd
  #    according to next test that tries to delete the first one, tcpdump-vnfd should
  #    not be deleted according to intelligent delete feature
  describe 'POST /tgo-packages' do
    context 'post packages simulating gatekeeper operation (posting all descriptors)' do
      before do
        filenames = %w[samples/dependencies_mapping/5gtango-test-package.tgo
                     samples/dependencies_mapping/5gtango-ns-package.tgo]
        $tgop_uuids = []
        filenames.each do |filename|
          headers = { 'CONTENT_TYPE' => 'application/octet-stream',
                      'HTTP_CONTENT_DISPOSITION' => "attachment; filename=#{filename}" }
          response = post '/tgo-packages', File.binread(filename), headers
          tgo_body = JSON.parse(response.body)
          $tgop_uuids << tgo_body['uuid']
          $tgo_filenames = filenames
        end
      end
      subject { last_response }
      its(:status) { is_expected.to eq 201 }

    end
  end


  let(:vnf_descriptor) {Rack::Test::UploadedFile.new('samples/dependencies_mapping/myvnfd.json','application/json', true)}
  describe 'POST \'/api/v2/vnfs\'' do
    context 'with correct parameters' do
      it 'Submit a vnfd for tgo package mapping' do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        post '/vnfs', vnf_descriptor, headers
        expect(last_response.status).to eq(201)
        vnf_body = JSON.parse(last_response.body)
        $vnf_testpkg_uuid = vnf_body['uuid']
        $vnf_testpkg_name = (vnf_body['vnfd']['name'])
        $vnf_testpkg_vendor = (vnf_body['vnfd']['vendor'])
        $vnf_testpkg_version = (vnf_body['vnfd']['version'])
      end
    end
  end
  #
  let(:ns_descriptor) {Rack::Test::UploadedFile.new('samples/dependencies_mapping/mynsd.json','application/json', true)}
  describe 'POST \'/api/v2/network-services\'' do
    context 'with correct parameters' do
      it 'Submit a nsd' do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        post '/network-services', ns_descriptor, headers
        expect(last_response.status).to eq(201)
        ns_body = JSON.parse(last_response.body)
        $ns_testpkg_uuid = ns_body['uuid']
        $ns_testpkg_name = (ns_body['nsd']['name'])
        $ns_testpkg_vendor = (ns_body['nsd']['vendor'])
        $ns_testpkg_version = (ns_body['nsd']['version'])
      end
    end
  end


  describe 'POST /files' do
    context 'post arbitrary files' do
      before do
        $file_uuids = []
        filenames = ['samples/dependencies_mapping/cloud.init',
                     'samples/dependencies_mapping/MyExample']
        filenames.each do |filename|
          headers = { 'CONTENT_TYPE' => 'application/octet-stream',
                      'HTTP_CONTENT_DISPOSITION' => "attachment; filename=#{filename}" }
          response = post '/files', File.binread(filename), headers
          filebody = JSON.parse(response.body)
          $file_uuids << filebody['uuid']
          $file_names = filenames
        end
      end
      subject { last_response }
      its(:status) { is_expected.to eq 201 }
    end
  end


  let(:package_descriptor) {Rack::Test::UploadedFile.new('samples/dependencies_mapping/NAPD.json','application/json', true)}
  describe 'POST \'/api/v2/packages\'' do
    context 'with correct parameters' do
      it 'Submit a pd for tgo package mapping' do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        post '/packages', package_descriptor, headers
        pd_body = JSON.parse(last_response.body)
        $pd_testpkg_id = pd_body['uuid']
        pd_body = pd_body['pd']
        pd_body['package_content'].each do |content|
          if content['content-type'].split('.')[-1] == 'vnfd'
            content['id'] = {name: $vnf_testpkg_name.to_s,
                             vendor:$vnf_testpkg_vendor.to_s,
                             version:$vnf_testpkg_version.to_s }
            content['uuid'] = $vnf_testpkg_uuid.to_s
          elsif content['content-type'].split('.')[-1] == 'nsd'
            content['id'] = {name: $ns_testpkg_name.to_s,
                             vendor:$ns_testpkg_vendor.to_s,
                             version:$ns_testpkg_version.to_s }
            content['uuid'] = $ns_testpkg_uuid.to_s
          elsif content['content-type'].split('.')[-1] == 'tstd'
          content['id'] = {name: $ns_testpkg_name.to_s,
                           vendor:$ns_testpkg_vendor.to_s,
                           version:$ns_testpkg_version.to_s }
          content['uuid'] = $ns_testpkg_uuid.to_s
          else
            if content['source'].split('/')[-1] == $file_names[0].split('/')[-1]
              content['uuid'] = $file_uuids[0].to_s
            elsif content['source'].split('/')[-1] == $file_names[1].split('/')[-1]
              content['uuid'] = $file_uuids[1].to_s
            end
          end
        end
        pd_body['package_file_uuid'] = $tgop_uuids[0].to_s
        pd_body['package_file_name'] = $tgo_filenames[0].to_s
        delete '/packages_debug/' + $pd_testpkg_id.to_s
        post '/packages', pd_body.to_json, headers
        pd_body_fin = JSON.parse(last_response.body)
        $pd_testpkg_id_fin = pd_body_fin['uuid']
        expect(last_response.status).to eq(201)
      end
    end
  end
  # describe 'POST \'/api/v2/tgo-packages/mappings\'' do
  #   context 'with correct parameters' do
  #     it 'Submit a pd for tgo package mapping' do
  #       headers = { 'CONTENT_TYPE' => 'application/json' }
  #
  #       mapping = {}
  #       mapping['tgo_package_uuid'] = $tgop_uuids[1].to_s
  #       mapping['vnfds'] = []
  #       mapping['nsds'] = []
  #       mapping['files'] = []
  #       mapping['deps'] = []
  #       mapping['pd'] = {name: $pd_testpkg_name.to_s,
  #                    vendor: $pd_testpkg_vendor.to_s,
  #                    version: $pd_testpkg_version.to_s}
  #       mapping['vnfds'] << {name: $vnf_testpkg_name.to_s,
  #                       vendor: $vnf_testpkg_vendor.to_s,
  #                       version: $vnf_testpkg_version.to_s}
  #       mapping['nsds'] << {name: $ns_testpkg_name.to_s,
  #                       vendor: $ns_testpkg_vendor.to_s,
  #                       version: $ns_testpkg_version.to_s}
  #       mapping['files'] << {file_name: $file_names[0].to_s,
  #                        file_uuid: $file_uuids[0].to_s}
  #       post '/tgo-packages/mappings', mapping.to_json, headers
  #       expect(last_response.status).to eq(200)
  #     end
  #   end
  # end

  describe 'GET tgo-packages' do
    context 'with uuid given' do
      before do
        headers = { 'CONTENT_TYPE' => 'application/json' }
        get '/tgo-packages?' + $tgop_uuids[0].to_s, nil, headers
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
    end
  end
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

  # Tries to delete first package posted in previous test resulting
  describe 'DELETE /api/v2/packages' do
    context 'deleting pds' do
      before do
        puts 'Deleting sonata-demo.son'
        delete_response = delete '/packages/' + $pd_testpkg_id_fin.to_s
        puts delete_response.body
        puts
        expect(delete_response.status).to eq(200)
        result = JSON.parse(delete_response.body)
        expect(result['result']['delete']['vnfds'].length).to eq(1)
        expect(result['result']['delete']['vnfds'][0]['name']).to eq('myvnf')
        expect(result['result']['delete']['vnfds'][0]['vendor']).to eq('eu.5gtango')
        expect(result['result']['delete']['vnfds'][0]['version']).to eq('0.1')
        expect(result['result']['delete']['nsds'].length).to eq(1)
        expect(result['result']['delete']['nsds'][0]['name']).to eq('myns')
        expect(result['result']['delete']['nsds'][0]['vendor']).to eq('eu.5gtango')
        expect(result['result']['delete']['nsds'][0]['version']).to eq('0.1')
        expect(result['result']['delete']['files'].length).to eq(2)
        expect(result['result']['delete']['files'][0]['uuid']).to eq($file_uuids[1].to_s)
        expect(result['result']['delete']['files'][1]['uuid']).to eq($file_uuids[0].to_s)
      end
      subject { last_response }
      its(:status) { is_expected.to eq 200 }
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

end
