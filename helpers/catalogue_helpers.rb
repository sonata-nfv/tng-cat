##
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

# @see SonCatalogue
class SonataCatalogue < Sinatra::Application
  require 'json'
  require 'yaml'
  require 'digest/md5'
  require 'jwt'
  require 'zip'
  require 'pathname'
  require 'httparty'
  require 'mongoid-grid_fs'

  # Read config settings from config file
  # @return [String, Integer] the address and port of the API
  def read_config
    begin
      config = YAML.load_file('config/config.yml')
      puts config['address']
      puts config['port']
    rescue YAML::LoadError => e
      # If config file is not found or valid, return with errors
      logger.error "read config error: #{e}"
    end

    [config['address'], config['port']]
  end

  # Checks if a JSON message is valid
  # @param [JSON] message some JSON message
  # @return [Hash, nil] if the parsed message is a valid JSON
  # @return [Hash, String] if the parsed message is an invalid JSON
  def parse_json(message)
    # Check JSON message format
    begin
      parsed_message = JSON.parse(message) # parse json message
    rescue JSON::ParserError => e
      # If JSON not valid, return with errors
      logger.error "JSON parsing: #{e}"
      return message, e.to_s + "\n"
    end
    [parsed_message, nil]
  end

  # Checks if a YAML message is valid
  # @param [YAML] message some YAML message
  # @return [Hash, nil] if the parsed message is a valid YAML
  # @return [Hash, String] if the parsed message is an invalid YAML
  def parse_yaml(message)
    # Check YAML message format
    begin
      parsed_message = YAML.load(message) # parse YAML message
    rescue YAML::ParserError => e
      # If YAML not valid, return with errors
      logger.error "YAML parsing: #{e}"
      return message, e.to_s + "\n"
    end
    [parsed_message, nil]
  end

  # Translates a message from YAML to JSON
  # @param [YAML] input_yml some YAML message
  # @return [Hash, nil] if the input message is a valid YAML
  # @return [Hash, String] if the input message is an invalid YAML
  def yaml_to_json(input_yml)
    begin
      output_json = JSON.dump(input_yml)
    rescue
      logger.error 'Error parsing from YAML to JSON'
    end
    output_json
  end

  # Translates a message from JSON to YAML
  # @param [JSON] input_json some JSON message
  # @return [Hash, nil] if the input message is a valid JSON
  # @return [Hash, String] if the input message is an invalid JSON
  def json_to_yaml(input_json)
    require 'json'
    require 'yaml'
    begin
      output_yml = YAML.dump(JSON.parse(input_json))
    rescue
      logger.error 'Error parsing from JSON to YAML'
    end
    output_yml
  end

  def apply_limit_and_offset(input, offset= nil, limit= nil)
    @result = input
    @result = offset ? input.drop(offset.to_i) : @result
    @result = limit ? @result.first(limit.to_i) : @result
  end

  # Builds an HTTP link for pagination
  # @param [Integer] offset link offset
  # @param [Integer] limit link limit position
  def build_http_link_ns(offset, limit)
    link = ''
    # Next link
    next_offset = offset + 1
    next_nss = Ns.paginate(page: next_offset, limit: limit)
    address, port = read_config
    begin
      link << '<' + address.to_s + ':' + port.to_s + '/catalogues/network-services?offset=' + next_offset.to_s +
          '&limit=' + limit.to_s + '>; rel="next"' unless next_nss.empty?
    rescue
      logger.error 'Error Establishing a Database Connection'
    end
    unless offset == 1
      # Previous link
      previous_offset = offset - 1
      previous_nss = Ns.paginate(page: previous_offset, limit: limit)
      unless previous_nss.empty?
        link << ', ' unless next_nss.empty?
        link << '<' + address.to_s + ':' + port.to_s + '/catalogues/network-services?offset=' + previous_offset.to_s +
            '&limit=' + limit.to_s + '>; rel="last"'
      end
    end
    link
  end

  # Builds an HTTP pagination link header
  # @param [Integer] offset the pagination offset requested
  # @param [Integer] limit the pagination limit requested
  # @return [String] the built link to use in header
  def build_http_link_vnf(offset, limit)
    link = ''
    # Next link
    next_offset = offset + 1
    next_vnfs = Vnf.paginate(page: next_offset, limit: limit)

    address, port = read_config

    link << '<' + address.to_s + ':' + port.to_s + '/catalogues/vnfs?offset=' + next_offset.to_s + '&limit=' +
        limit.to_s + '>; rel="next"' unless next_vnfs.empty?
    unless offset == 1
      # Previous link
      previous_offset = offset - 1
      previous_vnfs = Vnf.paginate(page: previous_offset, limit: limit)
      unless previous_vnfs.empty?
        link << ', ' unless next_vnfs.empty?
        link << '<' + address.to_s + ':' + port.to_s + '/catalogues/vnfs?offset=' + previous_offset.to_s +
            '&limit=' + limit.to_s + '>; rel="last"'
      end
    end
    link
  end

  # Extension of build_http_link
  def build_http_link_ns_name(offset, limit, name)
    link = ''
    # Next link
    next_offset = offset + 1
    next_nss = Ns.paginate(page: next_offset, limit: limit)
    address, port = read_config
    begin
      link << '<' + address.to_s + ':' + port.to_s + '/catalogues/network-services/name/' + name.to_s +
          '?offset=' + next_offset.to_s + '&limit=' + limit.to_s + '>; rel="next"' unless next_nss.empty?
    rescue
      logger.error 'Error Establishing a Database Connection'
    end

    unless offset == 1
      # Previous link
      previous_offset = offset - 1
      previous_nss = Ns.paginate(page: previous_offset, limit: limit)
      unless previous_nss.empty?
        link << ', ' unless next_nss.empty?
        link << '<' + address.to_s + ':' + port.to_s + '/catalogues/network-services/name/' + name.to_s +
            '?offset=' + previous_offset.to_s + '&limit=' + limit.to_s + '>; rel="last"'
      end
    end
    link
  end

  def checksum(contents)
    result = Digest::MD5.hexdigest contents #File.read
    result
  end

  def keyed_hash(hash)
    Hash[hash.map { |(k, v)| [k.to_sym, v] }]
  end

  def clean_brack(string_with_brack)
    string_with_brack.split(/\(([^\)]+)\)|\[([^\)]+)\]|\{([^\)]+)\}/)[-1].scan(/\s+|\w+|"[^"]*"/)
        .reject { |token| token =~ /^\s+$/ }.map { |token| token.sub(/^"/, "").sub(/"$/, "") }
  end

  def modify_operators(key_partitioned, value)
    key = key_partitioned[0]
    if %w(in nin).include? key_partitioned[-1]
      value = clean_brack(value)
    end
    value = {'$' + key_partitioned[-1] => value}
    [key, value]
  end

  def add_descriptor_level(descriptor_type, parameters)
    new_parameters = {}
    meta_data = %w(page_number page_size _id uuid status state signature username md5 updated_at created_at)
    operators = %w(eq gt gte lt lte ne nin in)
    begin
      parameters.each { |k, v|
        if k == 'uuid'
          new_parameters.store('_id', v)
        else
          k, v = modify_operators(k.rpartition('.'), v) if operators.include? k.rpartition('.')[-1]
          if meta_data.include? k
            cur_key = k
          else
            cur_key = descriptor_type.to_s + '.' + k
          end
          if new_parameters.key? cur_key; new_parameters[cur_key].merge! v else new_parameters.store(cur_key, v) end
        end
      }
    rescue TypeError, NoMethodError
      json_error 400, 'Query is not feasible. For comparison operators in the same field, use only comparison prefixes'
    end
    keyed_hash(new_parameters)
  end

  # def add_descriptor_level(descriptor_type, parameters)
  #   new_parameters = {}
  #   meta_data = %w(offset limit _id uuid status state signature md5 updated_at created_at)
  #   parameters.each { |k, v|
  #     if meta_data.include? k
  #       if k == 'uuid'
  #         new_parameters.store( '_id', v)
  #       else
  #         new_parameters.store( k, v)
  #       end
  #     else
  #       new_parameters.store((descriptor_type.to_s + '.' + k), v)
  #     end
  #   }
  #   parameters = keyed_hash(new_parameters)
  # end

  class Pair
    attr_accessor :one, :two
    def initialize(one, two)
      @one = one
      @two = two
    end
  end

  # Method that returns an error code and a message in json format
  def json_error(code, message, component = '', operation = '', time = Time.now.utc)
    msg = {'error' => message}
    logger.cust_error(status:code, start_stop: 'STOP',
                      component: component, message: message,
                      operation: operation, time_elapsed: (Time.now.utc - time).to_s)
    halt code, {'Content-type' => 'application/json'}, msg.to_json
  end

  # Method that returns a code and a message in json format
  def json_return(code, message, component = '', operation = '', time = Time.now.utc)
    msg = {'OK' => message}
    logger.cust_info(status:code, start_stop: 'STOP',
                      component: component, message: message,
                      operation: operation, time_elapsed: (Time.now.utc - time).to_s)
    halt code, {'Content-type' => 'application/json'}, msg.to_json
  end

  def getcurb(url, headers={})
    Curl.get(url) do |req|
      req.headers = headers
    end
  end

  def postcurb(url, body)
    Curl.post(url, body) do |req|
      req.headers['Content-type'] = 'application/json'
      req.headers['Accept'] = 'application/json'
    end
  end

  # Check if it's a valid dependency mapping descriptor
  # @param [Hash] desc The descriptor
  # @return [Boolean] true if descriptor contains name-vendor-version info
  def trio_dep_mapping_hash?(desc, value)
    { desc + '.name' => value['name'], desc + '.vendor' => value['vendor'],
      desc + '.version' => value['version'] }
  end

  def examine_descs_arr(content, coll, desc, info)
    content.each do |value|
      begin
        coll.find_by(trio_dep_mapping_hash?(desc, value))
      rescue Mongoid::Errors::DocumentNotFound
        json_error 400, "#{info} with {name => #{value['name']}, vendor => #{value['vendor']}, version => #{value['version']}} not found in the Catalogue"
      end
    end
  end


  def examine_descs_hash(content, coll, desc, info)
    begin
      desc_exam = coll.find_by(trio_dep_mapping_hash?(desc, content))
    rescue Mongoid::Errors::DocumentNotFound
      json_error 400, "#{info} with {name => #{content['name']}, vendor => #{content['vendor']}, version => #{content['version']}} not found in the Catalogue"
    end
    desc_exam
  end

  # Evaluate the package mapping file in order to provide independency of the catalogues
  # from the type of the package. Also, check the existence of
  # every descriptor and file inside the Catalogues. Schema can be found inside the
  # @param [StringIO] mapping_file The mapping file
  # @return [Boolean] Document containing the dependencies mapping
  def tgo_package_dep_mapping(mapping_file, tgopkg)
    pkg_desc = {}
    mapping_file.each do |field, content|
      case field
        when 'pd'
          if content.empty?
            json_error 400, 'Empty package descriptor trio', component, operation, time_req_begin
          else
            pkg_desc = examine_descs_hash(content, Pkgd, 'pd', 'PD Descriptor')
          end
        when 'vnfds'
          examine_descs_arr(content, Vnfd,'vnfd', 'VNF Descriptor')
        when 'nsds'
          examine_descs_arr(content, Nsd, 'nsd', 'NS Descriptor')
        when 'testds'
          examine_descs_arr(content, Testd, 'testd', 'TEST Descriptor')
        when 'files'
          content.each do |field|
            begin
              Files.find_by('file_name' => field['file_name'],
                                      '_id' => field['file_uuid'] )
            rescue Mongoid::Errors::DocumentNotFound
              json_error 400, "File with {name => #{field['file_name']}, uuid => #{field['file_uuid']}} not found in the Catalogue"
            end
          end
        end
    end
    if pkg_desc['package_file_name'].nil? && pkg_desc['package_file_id'].nil?
      pkg_desc.update_attributes(package_file_id: tgopkg['_id'],
                            package_file_name: tgopkg['package_name'])
    else
      json_error 400, "Package Desriptor {id => #{pkg_desc['_id']}} already mapped to package"
    end
    true
  end


  # Method returning packages depending on a descriptor
  # @param [Symbol] desc_type descriptor type (:vnfds, :nsds, :deps)
  # @param [Hash] desc descriptor hash
  # @param [Hash] target_package Target package to check
  # @param [Boolean] active_criteria true: checks the status of the package avoiding returning deps on inactive ones
  # @return [Boolean] true if there is some other package (different from target) depending on the descriptor
  def check_dependencies(desc, target_package = nil, active_criteria = false)
    # dependent_packages = Pkgd.where(
    #     { 'pd.package_content'  => { '$elemMatch' => { 'id.name' => desc['id'][:name],
    #                                                 'id.vendor' => desc['id'][:vendor],
    #                                                 'id.version' => desc['id'][:version] } } })
    # dependent_packages.each do |dp|
    #   diffp_condition = true
    #   if target_package != nil
    #     diffp_condition = ( (dp['pd']['name'] != target_package['name']) or
    #         (dp['pd']['vendor'] != target_package['vendor']) or
    #         (dp['pd']['version'] != target_package['version']) )
    #   end
    #   if diffp_condition
    #     if active_criteria
    #       return true if dp['status'].casecmp('ACTIVE') == 0
    #     else
    #       return true
    #     end
    #   end
    # end
    false
  end

  def check_dependencies_files(desc, target_package = nil, active_criteria = false)
    dependent_files = Pkgd.where(
        { 'pd.package-content' => { '$elemMatch' => {uuid: desc[:uuid]}}})
    dependent_files.each do |dp|
      diffp_condition = true
      if target_package != nil
        diffp_condition = ( (dp['pd']['name'] != target_package['name']) or
            (dp['pd']['vendor'] != target_package['vendor']) or
            (dp['pd']['version'] != target_package['version']) )
      end
      if diffp_condition
        if active_criteria
          return true if dp['status'].casecmp('ACTIVE') == 0
        else
          return true
        end
      end
    end
    false
  end

  # # # Method returning boolean depending if there is some instance of a descriptor
  # # # @param [Symbol] desc_type Descriptor type (:vnfd, :nsd)
  # # # @param [Hash] descriptor Descriptor hash
  # # # @return [Boolean] true/false
  # def instanced_descriptor?(desc_type, descriptor)
  #   if desc_type == :vnfd
  #     desc = Vnfd.where({ 'vnfd.name' => descriptor['name'],
  #                         'vnfd.vendor' => descriptor['vendor'],
  #                         'vnfd.version' => descriptor['version'] }).first
  #     return false if desc.nil?
  #     instances = Vnfr.where({ 'descriptor_reference' => desc['_id'] }).count
  #   elsif desc_type == :nsd
  #     desc = Nsd.where({ 'nsd.name' => descriptor['name'],
  #                        'nsd.vendor' => descriptor['vendor'],
  #                        'nsd.version' => descriptor['version'] }).first
  #     return false if desc.nil?
  #     instances = Nsr.where({ 'descriptor_reference' => desc['_id'] }).count
  #   end
  #   if instances > 0
  #     return true
  #   end
  #   return false
  # end

  # Method returning boolean depending if there is some instance of a descriptor
  # @param [Symbol] desc_type Descriptor type (:vnfd, :nsd)
  # @param [Hash] descriptor Descriptor hash
  # @return [Boolean] true/false
  def instanced_descriptor?(desc_type, descriptor)
    if desc_type == :vnfd
      desc = Vnfd.where({ 'vnfd.name' => descriptor['id']['name'],
                          'vnfd.vendor' => descriptor['id']['vendor'],
                          'vnfd.version' => descriptor['id']['version'] }).first
      return false if desc.nil?
      # instances = Vnfr.where( 'descriptor_reference' => desc['_id'] }).count
      begin
        resp_rep = HTTParty.get('https://tng-rep:4011/records/vnfr/descriptor_reference=' + desc['_id'],
                               headers: {'Content-Type' => 'applications/json'})
      rescue HTTParty::Error, StandardError => error
        logger.info error.inspect
        return false
      end
    elsif desc_type == :nsd
      desc = Nsd.where({ 'nsd.name' => descriptor['id']['name'],
                         'nsd.vendor' => descriptor['id']['vendor'],
                         'nsd.version' => descriptor['id']['version'] }).first
      return false if desc.nil?
      begin
        resp_rep = HTTParty.get('https://tng-rep:4011/records/nsr/descriptor_reference=' + desc['_id'],
                               headers: {'Content-Type' => 'applications/json'})
      rescue HTTParty::Error, StandardError => error
        logger.info error.inspect
        return false
      end
    elsif desc_type == :testd
      desc = Testd.where({ 'testd.name' => descriptor['id']['name'],
                          'testd.vendor' => descriptor['id']['vendor'],
                          'testd.version' => descriptor['id']['version'] }).first
      return false if desc.nil?
      # instances = Vnfr.where( 'descriptor_reference' => desc['_id'] }).count
      begin
        resp_rep = HTTParty.get('https://tng-rep:4011/records/vnfr/descriptor_reference=' + desc['_id'],
                                headers: {'Content-Type' => 'applications/json'})
      rescue HTTParty::Error, StandardError => error
        logger.info error.inspect
        return false
      end
    end
    return true if resp_rep.success?
    false
  end


  # Method returning descritptor information depending if there's one component instanced
  # @param [Pkgd] package Package descriptor model
  # @return [Hash] instantiated vnfds and nsds arrays
  # content['content-type'].split('.')[-1] == 'nsd'
  def instanced_components(mapping)
    vnfds = []
    nsds = []
    testds = []
    mapping.each do |content|
      next if content['content-type'].split('.')[-2] == 'osm'
      if content['content-type'].split('.')[-1] == 'vnfd'
        if instanced_descriptor?(:vnfd, content)
          vnfds << content['id']
        end
      elsif content['content-type'].split('.')[-1] == 'nsd'
        if instanced_descriptor?(:nsd, content)
          nsds << content['id']
        end
      elsif content['content-type'].split('.')[-1] == 'testd'
        if instanced_descriptor?(:testd, content)
          testds << content['id']
        end
      end
    end
    {vnfds: vnfds, nsds: nsds, testds: testds}
  end


  # Method returning Hash containing Vnfds and Nsds that can safely be disabled/deleted
  #     with no dependencies on other packages
  # @param [Pkgd] package Package descriptor model
  # @return [Hash] disable/delete and cant_disable/cant_delete vnfds and nsds
  # Method returning Hash containing Vnfds and Nsds that can safely be deleted
  #     with no dependencies on other packages
  # @param [Symbol] nodeps_sym Optional parameter key for no dependent components
  # @param [Symbol] deps_sym Optional parameter key for dependent components
  # @param [Boolean] active_criteria Optional (default false) parameter in order to ignore inactive dependencies
  # @return [Hash] delete/disable and cant_delete/cant_disable vnfds and nsds
  def intelligent_nodeps(mapping, package, nodeps_sym = :delete, deps_sym = :cant_delete, active_criteria = false)
    vnfds, nsds, testds, files, cant_delete_vnfds = [], [], [], [], []
    cant_delete_nsds, cant_delete_testds, cant_delete_files = [], [], []
    mapping.each do |content|
      next if content['content-type'].split('.')[-2] == 'osm'
      if content['content-type'].split('.')[-1] == 'vnfd'
        if check_dependencies( content, package.pd, active_criteria)
          logger.info 'VNFD ' + content['id'][:name] + ' has more than one dependency'
          cant_delete_vnfds << content['id']
        else
          vnfds << content['id']
        end
      elsif content['content-type'].split('.')[-1] == 'nsd'
        if check_dependencies(content, package.pd, active_criteria)
          logger.info 'NSD ' + content['id'][:name] + ' has more than one dependency'
          cant_delete_nsds << content['id']
        else
          nsds << content['id']
        end
      elsif content['content-type'].split('.')[-1] == 'tstd'
        if check_dependencies(content, package.pd, active_criteria)
          logger.info 'TESTD ' + content['id'][:name] + ' has more than one dependency'
          cant_delete_testds << content['id']
        else
          testds << content['id']
        end
      elsif content['content-type'].split('.')[-1] != 'ref'
        if check_dependencies_files(content, package.pd, active_criteria)
          logger.info 'File with {uuid =>' + content[:uuid] + '} has more than one dependency'
          cant_delete_files << {uuid: content[:uuid]}
        else
          files << {uuid: content[:uuid]}
        end
      end
    end
    { nodeps_sym => { vnfds: vnfds, nsds: nsds, testds: testds, files: files },
      deps_sym => { vnfds: cant_delete_vnfds, nsds: cant_delete_nsds,
                  testds: cant_delete_testds, files: cant_delete_files} }
  end

  # Method deleting vnfds from name, vendor, version
  # @param [Array] vnfds array of hashes
  # @return [Array] Not found array
  def delete_vnfds(vnfds)
    not_found = []
    vnfds.each do |vnfd_td|
      descriptor = Vnfd.where({ 'vnfd.name' => vnfd_td['name'],
                                'vnfd.vendor' => vnfd_td['vendor'],
                                'vnfd.version' => vnfd_td['version'] }).first
      if descriptor.nil?
        logger.error 'VNFD Descriptor not found'
        not_found << vnfd_td
      else
        if descriptor['pkg_ref'] == 1
         descriptor.destroy
         del_ent_dict(descriptor, :vnfd)
        else descriptor.update_attributes(pkg_ref: descriptor['pkg_ref'] - 1)
        end
      end
    end
    not_found
  end

  # Method deleting nsds from name, vendor, version
  # @param [Array] nsds nsds array of hashes
  # @return [Array] Not found array
  def delete_nsds(nsds)
    not_found = []
    nsds.each do |nsd_td|
      descriptor = Nsd.where({ 'nsd.name' => nsd_td['name'],
                               'nsd.vendor' => nsd_td['vendor'],
                               'nsd.version' => nsd_td['version'] }).first
      if descriptor.nil?
        logger.error 'NSD Descriptor not found ' + nsd_td.to_s
        not_found << nsd_td
      else
        if descriptor['pkg_ref'] == 1
          descriptor.destroy
          del_ent_dict(descriptor, :nsd)
        else descriptor.update_attributes(pkg_ref: descriptor['pkg_ref'] - 1)
        end
      end
    end
    not_found
  end

  # Method deleting testds from name, vendor, version
  # @param [Array] testds testds array of hashes
  # @return [Array] Not found array
  def delete_testds(testds)
    not_found = []
    testds.each do |testd_td|
      descriptor = Testd.where({ 'testd.name' => testd_td['name'],
                               'testd.vendor' => testd_td['vendor'],
                               'testd.version' => testd_td['version'] }).first
      if descriptor.nil?
        logger.error 'Test Descriptor not found ' + testd_td.to_s
        not_found << testd_td
      else
        if descriptor['pkg_ref'] == 1
          descriptor.destroy
          del_ent_dict(descriptor, :testd)
        else descriptor.update_attributes(pkg_ref: descriptor['pkg_ref'] - 1)
        end
      end
    end
    not_found
  end
  # Method deleting testds from name, vendor, version
  # @param [Array] testds testds array of hashes
  # @return [Array] Not found array
  def delete_files(files)
    not_found = []
    files.each do |file|
      file_stored = Files.where({ '_id' => file[:uuid]}).first
      if file_stored.nil?
        logger.error 'File not found ' + file.to_s
        not_found << file
      else
        if file_stored['pkg_ref'] == 1
          # Referenced only once. Delete in this case
          file_stored.destroy
          del_ent_dict(file_stored, :files)
          file_md5 = Files.where('md5' => file_stored['md5'])
          if file_md5.size.to_i.zero?
            # Remove files from grid
            grid_fs = Mongoid::GridFs
            grid_fs.delete(file_stored['grid_fs_id'])
          end
        else
          # Referenced above once. Decrease counter
          file_stored.update_attributes(pkg_ref: file_stored['pkg_ref'] - 1)
        end
        # file_stored.destroy
        # del_ent_dict(file_stored, :files)
        #
        # # Remove files from grid
        # grid_fs = Mongoid::GridFs
        # grid_fs.delete(file_stored['grid_fs_id'])
      end
    end
    not_found
  end

  # Method deleting pd and also dependencies mapping
  # @param [Hash] descriptor model hash
  # @return [void]
  def delete_pd(descriptor)
    # # first find dependencies_mapping
    # pkg = FileContainer.find_by('_id' => descriptor['pd']['package_file_uuid'])

    # first find dependencies_mapping
    pkg = FileContainer.find_by('_id' => descriptor['pd']['package_file_uuid'])

    if pkg['pkg_ref'] == 1
      # Referenced only once. Delete in this case
      pkg.destroy
      tgop_md5 = Files.where('md5' => pkg['md5'])
      if tgop_md5.size.to_i.zero?
        # Remove files from grid
        grid_fs = Mongoid::GridFs
        grid_fs.delete(pkg['grid_fs_id'])
      end
    else
      # Referenced above once. Decrease counter
      pkg.update_attributes(pkg_ref: pkg['pkg_ref'] - 1)
    end
    descriptor.destroy
    del_ent_dict(descriptor, :pd)
    # descriptor.destroy
    # del_ent_dict(descriptor, :pd)
    # grid_fs = Mongoid::GridFs
    # grid_fs.delete(pkg['grid_fs_id'])
    # pkg.destroy
    # descriptor.destroy
  end

  # Method Set status of vnfds from name, vendor, version
  # @param [Array] vnfds array of hashes
  # @param [String] status Desired status
  # @return [Array] Not found array
  def set_vnfds_status(vnfds, status)
    not_found = []
    vnfds.each do |vnfd_td|
      descriptor = Vnfd.where({ 'vnfd.name' => vnfd_td['name'],
                                'vnfd.vendor' => vnfd_td['vendor'],
                                'vnfd.version' => vnfd_td['version'] }).first
      if descriptor.nil?
        logger.error 'VNFD Descriptor not found'
        not_found << vnfd_td
      else
        descriptor.update('status' => status)
      end
    end
    not_found
  end

  # Method Set status of nsds from name, vendor, version
  # @param [Array] nsds nsds array of hashes
  # @param [String] status Desired status
  # @return [Array] Not found array
  def set_nsds_status(nsds, status)
    not_found = []
    nsds.each do |nsd_td|
      descriptor = Nsd.where({ 'nsd.name' => nsd_td['name'],
                               'nsd.vendor' => nsd_td['vendor'],
                               'nsd.version' => nsd_td['version'] }).first
      if descriptor.nil?
        logger.error 'NSD Descriptor not found ' + nsd_td.to_s
        not_found << nsd_td
      else
        descriptor.update('status' => status)
      end
    end
    not_found
  end

  # Method Set status of a pd
  # @param [Hash] descriptor model hash
  # @param [String] status Desired status
  # @return [void]
  def set_pd_status(descriptor, status)
    # first find dependencies_mapping
    package_deps = Dependencies_mapping.where('pd.name' => descriptor['pd']['name'],
                                              'pd.vendor' => descriptor['pd']['vendor'],
                                              'pd.version' => descriptor['pd']['version'])
    descriptor.update('status' => status)
    package_deps.each do |package_dep|
      package_dep.update('status' => status)
    end
  end

  # #Method of fetching package mapping metadata from package descriptor
  # def fetch_pkg_mapping(pks)
  #   if pks['package_file_id'].nil?
  #     logger.debug "Catalogue: leaving DELETE /api/v2/packages?#{query_string}\" with PD #{pks}"
  #     pks.destroy
  #     json_return 200, "Mapping package file not found. Delete only PD {_id => #{pks['_id']}"
  #   else
  #     pkg = FileContainer.find_by('_id' => pks['package_file_id'])
  #   end
  #   pkg['mapping']
  # end

  # Method deleting pd from name, vendor, version
  # @param [Hash] pks Package model hash
  # @return [void]
  def intelligent_delete(pks)
    mapping = pks['pd']['package_content']
    icomps = instanced_components(mapping)
    halt 500, JSON.generate(error: 'Can\'t search for instanced components') if icomps.nil?
    if ( icomps[:vnfds].length > 0 ) or ( icomps[:nsds].length > 0 ) or ( icomps[:testds].length > 0 )
      halt 409, JSON.generate(error: 'Instanced elements cannot be deleted.',
                              components: { vnfds: icomps[:vnfds],
                                            nsds: icomps[:nsds],
                                            testds: icomps[:testds]} )
    end
    todelete = intelligent_nodeps(mapping, pks)
    logger.info 'COMPONENTS WITHOUT DEPENDENCIES: ' + todelete.to_s
    not_found_vnfds = delete_vnfds(todelete[:delete][:vnfds])
    not_found_nsds = delete_nsds(todelete[:delete][:nsds])
    not_found_testds = delete_testds(todelete[:delete][:testds])
    not_found_files = delete_files(todelete[:delete][:files])
    delete_pd(pks)
    if (not_found_vnfds.length == 0 and not_found_nsds.length == 0 and not_found_testds.length == 0 and not_found_files.length == 0 )
      logger.debug "Catalogue: leaving DELETE /api/v2/packages?#{query_string}\" with PD #{pks}"
      halt 200, JSON.generate(result: todelete)
    else
      logger.debug "Catalogue: leaving DELETE /api/v2/packages?#{query_string}\" with PD #{pks}"
      logger.info "Some descriptors where not found"
      logger.info "Vnfds not found: " + not_found_vnfds.to_s
      logger.info "Nsds not found: " + not_found_nsds.to_s
      logger.info "Testds not found: " + not_found_testds.to_s
      logger.info "Files not found: " + not_found_files.to_s
      halt 404, JSON.generate(result: todelete,
                              not_found: { vnfds: not_found_vnfds, nsds: not_found_nsds,
                                           testds: not_found_testds, files: not_found_files})
    end
  end

  # Method deleting pd from name, vendor, version
  # @param [Hash] pks Package model hash
  # @return [void]
  def intelligent_disable(pks)
    todisable = intelligent_nodeps(pks, :disable, :cant_disable, true)
    logger.info 'COMPONENTS WITHOUT DEPENDENCIES: ' + todisable.to_s
    not_found_vnfds = set_vnfds_status(todisable[:disable][:vnfds], 'inactive')
    not_found_nsds = set_nsds_status(todisable[:disable][:nsds], 'inactive')
    set_pd_status(pks, 'inactive')
    if ( not_found_vnfds.length == 0 ) and ( not_found_nsds.length == 0 )
      logger.debug "Catalogue: leaving DISABLE /api/v2/packages?#{query_string}\" with PD #{pks}"
      halt 200, JSON.generate(result: todisable)
    else
      logger.debug "Catalogue: leaving DISABLE /api/v2/packages?#{query_string}\" with PD #{pks}"
      logger.info "Some descriptors where not found "
      logger.info "Vnfds not found: " + not_found_vnfds.to_s
      logger.info "Nsds not found: " + not_found_nsds.to_s
      halt 404, JSON.generate(result: todisable,
                              not_found: { vnfds: not_found_vnfds, nsds: not_found_nsds })
    end
  end

  # Method deleting pd from name, vendor, version
  # @param [Hash] pks Package model hash
  # @return [void]
  def intelligent_enable_all(pks)
    begin
      pattern = { 'pd.name' => pks.pd['name'],
                  'pd.version' => pks.pd['version'],
                  'pd.vendor' => pks.pd['vendor'] }
      pdep_mapping = Dependencies_mapping.find_by(pattern)
    rescue Mongoid::Errors::DocumentNotFound => e
      logger.error 'Dependencies not found: ' + e.message
      # If no document found, avoid to delete descriptors blindly
      return { nodeps_sym => { vnfds: [], nsds: [] } }
    end
    not_found_vnfds = set_vnfds_status(pdep_mapping.vnfds, 'active')
    not_found_nsds = set_nsds_status(pdep_mapping.nsds, 'active')
    set_pd_status(pks, 'active')
    if ( not_found_vnfds.length == 0 ) and ( not_found_nsds.length == 0 )
      logger.debug "Catalogue: leaving DISABLE /api/v2/packages?#{query_string}\" with PD #{pks}"
      halt 200, JSON.generate(result: { enable: { vnfds: pdep_mapping.vnfds,
                                                nsds: pdep_mapping.nsds } })
    else
      logger.debug "Catalogue: leaving DISABLE /api/v2/packages?#{query_string}\" with PD #{pks}"
      logger.info "Some descriptors where not found "
      logger.info "Vnfds not found: " + not_found_vnfds.to_s
      logger.info "Nsds not found: " + not_found_nsds.to_s
      halt 404, JSON.generate(result: { enable: { vnfds: pdep_mapping.vnfds,
                                                nsds: pdep_mapping.nsds } },
                              not_found: { vnfds: not_found_vnfds, nsds: not_found_nsds })
    end
  end

  def number?(object)
    true if Float(object)
  rescue
    false
  end

  def compare_objects(method, first_obj, second_obj)
    state = if number? second_obj
              map_operators(method, Float(first_obj), Float(second_obj))
            else
              map_operators(method, first_obj, second_obj)
            end
    state
  rescue ArgumentError
    json_error 404, 'No ability of comparing different types of objects'
  end

  def map_operators(method, first_n, second_n)
    case method
      when 'eq'
        first_n == second_n
      when 'gt'
        first_n > second_n
      when 'gte'
        first_n >= second_n
      when 'lt'
        first_n < second_n
      when 'lte'
        first_n <= second_n
      when 'neq'
        first_n != second_n
      when 'in'
        second_n.include? first_n
      when 'nin'
        !(second_n.include? first_n)
    end
  end

  # Transform the params for search into sequence of stored ids
  # @param [Dict] params from CURL
  # @param [Dict] keyed_params from CURL
  # @param [Symbol] type_of_descriptor is valid symbol from the hosted type of descriptors
  # @return [Object] keyed_params is dict with replaced the values of the inverted index
  def parse_keys_dict(type_of_descriptor, keyed_params)
    paths_dict =  parse_dict(type_of_descriptor)
    cur_array_id = []
    array_id = []
    cur_bool = true
    keyed_params.each do |key, value|
      keys = key.to_s.split('.')[-1]
      if paths_dict.key? keys.to_sym
        keyed_params.delete((type_of_descriptor.to_s + '.' + keys).to_sym)
        value.class == String ?
            Dict.all.each {|field_of_dict| cur_array_id += field_of_dict[keys][value] unless field_of_dict[keys][value].empty?}:
            Dict.all.each do |field_of_dict|
              field_of_dict.as_document[keys].keys.each do |key_field_dict|
                value.each {|key, value| cur_bool &= compare_objects(key.split('$')[-1], key_field_dict, value)}
                cur_array_id += field_of_dict[keys][key_field_dict] if cur_bool
                cur_bool = true
              end
            end
      end
      array_id = cur_array_id.select{ |e| cur_array_id.count(e) >= keyed_params.length }.uniq
    end
    keyed_params[:'_id'.in] = array_id unless array_id == 1 || array_id.empty?
    keyed_params
  end

  def insert_val_dict(init, key, value, desc)
    if init.empty? || !(init.key? key.to_s)
      init[key.to_s + '.' + value.to_s] = desc['_id']
    else
      init[key.to_s + '.' + value.to_s].merge!(desc['_id'])
    end
    init
  end


  # Update dictionary with appropriate entries of new descriptors
  # @param [Symbol] type_of_descriptor is symbol referencing the type of descriptor
  # @param [Hash] desc is the new descriptor to be hosted
  # @param [Hash] init is an empty hash for storing the params for query
  # @return init is the parameters for query
  def update_dict(type_of_descriptor,desc,init)
    paths_dict = parse_dict(type_of_descriptor)
    paths_dict.each do |key,value|
      path = JsonPath.new(value)
      next unless path.on(desc).any?
      path.on(desc).each do |value_of_field|
        if value_of_field.is_a? Array
          value_of_field.each {|value_of_array| init = insert_val_dict(init, key, value_of_array, desc) }
        else
          init = insert_val_dict(init, key, value_of_field, desc)
        end
      end
    end
    init
  end

  # Return of the appropriate dictionary
  # @param [Symbol] type_of_descriptor
  # @return [Hash] is the inverted index for every descriptor
  def parse_dict(type_of_descriptor)
    dict = {vnfd: {
        memory_size: '$..memory.size',
        storage_size: '$..storage.size',
    },
            testd: {
                test_tag: '$..test_tag'

            },
            nsd: {
                testing_tags: '$..testing_tags'
            },
            slad: {
                ns_id: '$..ns_id'
            },
            nstd: {},
            files: {},
            pld: {

            },
            pd: {}
    }
    dict[type_of_descriptor]
  end

  def del_ent_dict(desc_as_doc, type_of_desc)
    doc = Hash.new()
    desc = desc_as_doc.as_document
    doc = update_dict(type_of_desc,desc,doc)
    desc = Dict.all.pull(doc) if doc.any?
    doc.each do |key, value|
      desc = Dict.where(key => []).unset(key)
      desc = Dict.where(key.split('.').first => {}).unset(key.split('.').first)
    end
  end

  def update_entr_dict(desc_as_doc, type_of_desc)
    doc = Hash.new()
    begin
      desc = Dict.create!() if Dict.count == 0
      doc = update_dict(type_of_desc, desc_as_doc, doc)
      desc = Dict.all.push(doc) if doc.any?
    rescue Moped::Errors::OperationFailure => e
      logger.error e
      json_error 404, 'Unable to refresh dictionary' unless desc
    end
  end

  # Method which lists all available interfaces
  # @return [Array] an array of hashes containing all interfaces
  def interfaces_list
    [
      {
        'uri' => '/catalogues',
        'method' => 'GET',
        'purpose' => 'REST API Structure and Capability Discovery'
      },
      {
        'uri' => '/catalogues/network-services',
        'method' => 'GET',
        'purpose' => 'List all NSs or specific NS',
        'special' => 'Use version=last to retrieve NSs last version'
      },
      {
        'uri' => '/catalogues/network-services/{id}',
        'method' => 'GET',
        'purpose' => 'List a specific NS by its uuid'
      },
      {
        'uri' => '/catalogues/network-services',
        'method' => 'POST',
        'purpose' => 'Store a new NS'
      },
      {
        'uri' => '/catalogues/network-services',
        'method' => 'PUT',
        'purpose' => 'Update a stored NS specified by vendor, name, version'
      },
      {
        'uri' => '/catalogues/network-services/{id}',
        'method' => 'PUT',
        'purpose' => 'Update a stored NS by its uuid',
        'special' => 'Use status=[inactive, active, delete] to update NSD status'
      },
      {
        'uri' => '/catalogues/network-services',
        'method' => 'DELETE',
        'purpose' => 'Delete a specific NS specified by vendor, name, version'
      },
      {
        'uri' => '/catalogues/network-services/{id}',
        'method' => 'DELETE',
        'purpose' => 'Delete a specific NS by its uuid'
      },
      {
        'uri' => '/catalogues/vnfs',
        'method' => 'GET',
        'purpose' => 'List all VNFs or specific VNF',
        'special' => 'Use version=last to retrieve VNFs last version'
      },
      {
        'uri' => '/catalogues/vnfs/{id}',
        'method' => 'GET',
        'purpose' => 'List a specific VNF by its uuid'
      },
      {
        'uri' => '/catalogues/vnfs',
        'method' => 'POST',
        'purpose' => 'Store a new VNF'
      },
      {
        'uri' => '/catalogues/vnfs',
        'method' => 'PUT',
        'purpose' => 'Update a stored VNF specified by vendor, name, version'
      },
      {
        'uri' => '/catalogues/vnfs/{id}',
        'method' => 'PUT',
        'purpose' => 'Update a stored VNF by its uuid',
        'special' => 'Use status=[inactive, active, delete] to update VNFD status'
      },
      {
        'uri' => '/catalogues/vnfs',
        'method' => 'DELETE',
        'purpose' => 'Delete a specific VNF specified by vendor, name, version'
      },
      {
        'uri' => '/catalogues/vnfs/{id}',
        'method' => 'DELETE',
        'purpose' => 'Delete a specific VNF by its uuid'
      },
      {
        'uri' => '/catalogues/packages',
        'method' => 'GET',
        'purpose' => 'List all Packages or specific Package',
        'special' => 'Use version=last to retrieve Packages last version'
      },
      {
        'uri' => '/catalogues/packages/{id}',
        'method' => 'GET',
        'purpose' => 'List a specific Package by its uuid'
      },
      {
        'uri' => '/catalogues/packages',
        'method' => 'POST',
        'purpose' => 'Store a new Package'
      },
      {
        'uri' => '/catalogues/packages',
        'method' => 'PUT',
        'purpose' => 'Update a stored Package specified by vendor, name, version'
      },
      {
        'uri' => '/catalogues/packages/{id}',
        'method' => 'PUT',
        'purpose' => 'Update a stored Package by its uuid',
        'special' => 'Use status=[inactive, active, delete] to update PD status'
      },
      {
        'uri' => '/catalogues/packages',
        'method' => 'DELETE',
        'purpose' => 'Delete a specific Package specified by vendor, name, version'
      },
      {
        'uri' => '/catalogues/packages/{id}',
        'method' => 'DELETE',
        'purpose' => 'Delete a specific Package by its uuid'
      },
      {
        'uri' => '/catalogues/packages/{id}/status',
        'method' => 'PUT',
        'purpose' => 'Updates the status of a Package {"status": "active" / "inactive"} as valid json payloads'
      },
      {
        'uri' => '/catalogues/son-packages',
        'method' => 'GET',
        'purpose' => 'List all son-packages or specific son-package'
      },
      {
        'uri' => '/catalogues/son-packages',
        'method' => 'POST',
        'purpose' => 'Store a new son-package'
      },
      {
        'uri' => '/catalogues/son-packages/{id}',
        'method' => 'GET',
        'purpose' => 'List a specific son-package by its uuid'
      },
      {
        'uri' => '/catalogues/son-packages/{id}',
        'method' => 'DELETE',
        'purpose' => 'Remove a son-package'
      }
    ]
  end

  private
  def query_string
    request.env['QUERY_STRING'].nil? ? '' : request.env['QUERY_STRING'].to_s
  end

  def request_url
    request.env['rack.url_scheme'] + '://' + request.env['HTTP_HOST'] + request.env['REQUEST_PATH']
  end
end
