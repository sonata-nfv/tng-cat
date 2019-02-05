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
# class SonataCatalogue < Sinatra::Application
class CatalogueV1 < SonataCatalogue
  # require 'addressable/uri'

  ### VNFD API METHODS ###

  # @method get_vnfs
  # @overload get '/catalogues/vnfs/?'
  #	Returns a list of VNFs
  # -> List many descriptors
  get '/vnfs/?' do
    params['page_number'] ||= DEFAULT_PAGE_NUMBER
    params['page_size'] ||= DEFAULT_PAGE_SIZE

    # uri = Addressable::URI.new
    # uri.query_values = params
    # puts 'params', params
    # puts 'query_values', uri.query_values
    logger.info "Catalogue: entered GET /vnfs?#{query_string}"

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)
    # puts 'keyed_params', keyed_params

    # Set headers
    case request.content_type
      when 'application/x-yaml'
        headers = { 'Accept' => 'application/x-yaml', 'Content-Type' => 'application/x-yaml' }
      else
        headers = { 'Accept' => 'application/json', 'Content-Type' => 'application/json' }
    end
    headers[:params] = params unless params.empty?

    # Get rid of :page_number and :limit
    [:page_number, :page_size].each { |k| keyed_params.delete(k) }
    # puts 'keyed_params(1)', keyed_params

    # Check for special case (:version param == last)
    if keyed_params.key?(:version) && keyed_params[:version] == 'last'
      # Do query for last version -> get_vnfd_vnf_vendor_last_version

      keyed_params.delete(:version)
      # puts 'keyed_params(2)', keyed_params

      vnfs = Vnf.where((keyed_params)).sort({ 'version' => -1 }) #.limit(1).first()
      logger.info "Catalogue: VNFDs=#{vnfs}"
      # vnfs = vnfs.sort({"version" => -1})
      # puts 'vnfs: ', vnfs.to_json

      if vnfs && vnfs.size.to_i > 0
        logger.info "Catalogue: leaving GET /vnfs?#{query_string} with #{vnfs}"

        # Paginate results
        # vnfs = vnfs.paginate(:page_number => params[:page_number], :page_size => params[:page_size]).sort({"version" => -1})

        vnfs_list = []
        checked_list = []

        vnfs_name_vendor = Pair.new(vnfs.first.name, vnfs.first.vendor)
        # p 'vnfs_name_vendor:', [vnfs_name_vendor.one, vnfs_name_vendor.two]
        checked_list.push(vnfs_name_vendor)
        vnfs_list.push(vnfs.first)

        vnfs.each do |vnfd|
          # p 'Comparison: ', [vnfd.name, vnfd.vendor].to_s + [vnfs_name_vendor.one, vnfs_name_vendor.two].to_s
          if (vnfd.name != vnfs_name_vendor.one) || (vnfd.vendor != vnfs_name_vendor.two)
            vnfs_name_vendor = Pair.new(vnfd.name, vnfd.vendor)
          end
          vnfs_list.push(vnfd) unless checked_list.any? { |pair| pair.one == vnfs_name_vendor.one &&
              pair.two == vnfs_name_vendor.two }
          checked_list.push(vnfs_name_vendor)
        end
        # puts 'vnfs_list:', vnfs_list.each {|vnf| p vnf.name, vnf.vendor}
      else
        # logger.error "ERROR: 'No VNFDs were found'"
        logger.info "Catalogue: leaving GET /vnfs?#{query_string} with 'No VNFDs were found'"
        # json_error 404, "No VNFDs were found"
        vnfs_list = []
      end
      # vnfs = vnfs_list.paginate(:page => params[:page_number], :per_page =>params[:page_size])
      vnfs = apply_limit_and_offset(vnfs_list, page_number=params[:page_number], page_size=params[:page_size])

    else
      # Do the query
      vnfs = Vnf.where(keyed_params)
      logger.info "Catalogue: VNFDs=#{vnfs}"
      # puts vnfs.to_json
      if vnfs && vnfs.size.to_i > 0
        logger.info "Catalogue: leaving GET /vnfs?#{query_string} with #{vnfs}"

        # Paginate results
        vnfs = vnfs.paginate(page_number: params[:page_number], page_size: params[:page_size])

      else
        logger.info "Catalogue: leaving GET /vnfs?#{query_string} with 'No VNFDs were found'"
        # json_error 404, "No VNFDs were found"
      end
    end

    response = ''
    case request.content_type
      when 'application/json'
        response = vnfs.to_json
      when 'application/x-yaml'
        response = json_to_yaml(vnfs.to_json)
      else
        halt 415
    end
    halt 200, response
  end

  # @method get_vnfs_id
  # @overload get '/catalogues/vnfs/:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] id VNF ID
  # Show a VNF by internal ID (uuid)
  get '/vnfs/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: GET /vnfs/#{params[:id]}"

      begin
        vnf = Vnf.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The VNFD ID #{params[:id]} does not exist" unless vnf
      end
      logger.debug "Catalogue: leaving GET /vnfs/#{params[:id]}\" with VNFD #{vnf}"

      response = ''
      case request.content_type
        when 'application/json'
          response = vnf.to_json
        when 'application/x-yaml'
          response = json_to_yaml(vnf.to_json)
        else
          halt 415
      end
      halt 200, response

    end
    logger.debug "Catalogue: leaving GET /vnfs/#{params[:id]} with 'No VNFD ID specified'"
    json_error 400, 'No VNFD ID specified'
  end

  # @method post_vnfs
  # @overload post '/catalogues/vnfs'
  # Post a VNF in JSON or YAML format
  post '/vnfs' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a VNFD, the json object sent to API must contain just data inside
        # of the vnfd, without the json field vnfd: before
        vnf, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_vnf_json = yaml_to_json(vnf)

        # Validate JSON format
        new_vnf, errors = parse_json(new_vnf_json)
        # puts 'vnf: ', new_vnf.to_json
        # puts 'new_vnf id', new_vnf['_id'].to_json
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_vnf, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    # Validate VNF
    json_error 400, 'ERROR: VNF Vendor not found' unless new_vnf.has_key?('vendor')
    json_error 400, 'ERROR: VNF Name not found' unless new_vnf.has_key?('name')
    json_error 400, 'ERROR: VNF Version not found' unless new_vnf.has_key?('version')

    # --> Validation disabled
    # Validate VNFD
    # begin
    #	  postcurb settings.nsd_validator + '/nsds', ns.to_json, :content_type => :json
    # rescue => e
    #	  halt 500, {'Content-Type' => 'text/plain'}, "Validator mS unrechable."
    # end

    # Check if VNFD already exists in the catalogue by name, vendor and version
    begin
      vnf = Vnf.find_by({ 'name' => new_vnf['name'], 'vendor' => new_vnf['vendor'], 'version' => new_vnf['version'] })
      json_return 200, 'Duplicated VNF Name, Vendor and Version'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end
    # Check if VNFD has an ID (it should not) and if it already exists in the catalogue
    begin
      vnf = Vnf.find_by({ '_id' => new_vnf['_id'] })
      json_return 200, 'Duplicated VNF ID'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    # Save to DB
    begin
      # Generate the UUID for the descriptor
      new_vnf['_id'] = SecureRandom.uuid
      new_vnf['status'] = 'active'
      vnf = Vnf.create!(new_vnf)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated VNF ID' if e.message.include? 'E11000'
    end

    puts 'New VNF has been added'
    response = ''
    case request.content_type
      when 'application/json'
        response = vnf.to_json
      when 'application/x-yaml'
        response = json_to_yaml(vnf.to_json)
      else
        halt 415
    end
    halt 201, response
  end

  # @method update_vnfs
  # @overload put '/vnfs/?'
  # Update a VNF by vendor, name and version in JSON or YAML format
  ## Catalogue - UPDATE
  put '/vnfs/?' do
    # uri = Addressable::URI.new
    # uri.query_values = params
    # puts 'params', params
    # puts 'query_values', uri.query_values
    logger.info "Catalogue: entered PUT /vnfs?#{query_string}"

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)
    # puts 'keyed_params', keyed_params

    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Return if params are empty
    json_error 400, 'Update parameters are null' if keyed_params.empty?

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a VNFD, the json object sent to API must contain just data inside
        # of the vnfd, without the json field vnfd: before
        vnf, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_vnf_json = yaml_to_json(vnf)

        # Validate JSON format
        new_vnf, errors = parse_json(new_vnf_json)
        new_vnf, errors = parse_json(new_vnf_json)
        # puts 'vnf: ', new_vnf.to_json
        # puts 'new_vnf id', new_vnf['_id'].to_json
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_vnf, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    # Validate NS
    # Check if same vendor, Name, Version do already exists in the database
    json_error 400, 'ERROR: VNF Vendor not found' unless new_vnf.has_key?('vendor')
    json_error 400, 'ERROR: VNF Name not found' unless new_vnf.has_key?('name')
    json_error 400, 'ERROR: VNF Version not found' unless new_vnf.has_key?('version')

    # Set headers
    case request.content_type
      when 'application/x-yaml'
        headers = { 'Accept' => 'application/x-yaml', 'Content-Type' => 'application/x-yaml' }
      else
        headers = { 'Accept' => 'application/json', 'Content-Type' => 'application/json' }
    end
    headers[:params] = params unless params.empty?

    # Retrieve stored version
    if keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      json_error 400, 'Update Vendor, Name and Version parameters are null'
    else
      begin
        vnf = Vnf.find_by({ 'vendor' => keyed_params[:vendor], 'name' => keyed_params[:name],
                            'version' => keyed_params[:version] })
        puts 'VNF is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The VNFD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
    end
    # Check if VNF already exists in the catalogue by name, group and version
    begin
      vnf = Vnf.find_by({ 'name' => new_vnf['name'], 'vendor' => new_vnf['vendor'], 'version' => new_vnf['version'] })
      json_return 200, 'Duplicated VNF Name, Vendor and Version'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    # Update to new version
    puts 'Updating...'
    new_vnf['_id'] = SecureRandom.uuid # Unique UUIDs per VNFD entries
    vnfd = new_vnf

    # --> Validation disabled
    # Validate VNFD
    #begin
    #	postcurb settings.nsd_validator + '/nsds', nsd.to_json, :content_type => :json
    #rescue => e
    #	logger.error e.response
    #	return e.response.code, e.response.body
    #end

    begin
      new_vnf = Vnf.create!(vnfd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated VNF ID' if e.message.include? 'E11000'
    end
    logger.debug "Catalogue: leaving PUT /vnfs?#{query_string}\" with VNFD #{new_vnf}"

    response = ''
    case request.content_type
      when 'application/json'
        response = new_vnf.to_json
      when 'application/x-yaml'
        response = json_to_yaml(new_vnf.to_json)
      else
        halt 415
    end
    halt 200, response
  end

  # @method update_vnfs_id
  # @overload put '/catalogues/vnfs/:id/?'
  #	Update a VNF by its ID in JSON or YAML format
  ## Catalogue - UPDATE
  put '/vnfs/:id/?' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?
      logger.debug "Catalogue: PUT /vnfs/#{params[:id]}"

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)
      # puts 'keyed_params', keyed_params

      # Check for special case (:status param == <new_status>)
      if keyed_params.key?(:status)
        # Do update of Descriptor status -> update_ns_status
        # uri = Addressable::URI.new
        # uri.query_values = params
        logger.info "Catalogue: entered PUT /vnfs/#{query_string}"

        # Validate VNF
        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          vnf = Vnf.find_by({ '_id' => params[:id] })
          puts 'VNF is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This VNFD does not exists'
        end

        #Validate new status
        valid_status = %w(active inactive delete)
        if valid_status.include? keyed_params[:status]
          # Update to new status
          begin
            #vnf.update_attributes(:status => params[:new_status])
            vnf.update_attributes(status: keyed_params[:status])
          rescue Moped::Errors::OperationFailure => e
            json_error 400, 'ERROR: Operation failed'
          end
        else
          json_error 400, "Invalid new status #{keyed_params[:status]}"
        end

        # --> Validation disabled
        # Validate VNFD
        #begin
        #	postcurb settings.nsd_validator + '/nsds', nsd.to_json, :content_type => :json
        #rescue => e
        #	logger.error e.response
        #	return e.response.code, e.response.body
        #end

        halt 200, "Status updated to {#{query_string}}"

      else
        # Compatibility support for YAML content-type
        case request.content_type
          when 'application/x-yaml'
            # Validate YAML format
            # When updating a VNFD, the json object sent to API must contain just data inside
            # of the vnfd, without the json field vnfd: before
            vnf, errors = parse_yaml(request.body.read)
            halt 400, errors.to_json if errors

            # Translate from YAML format to JSON format
            new_vnf_json = yaml_to_json(vnf)

            # Validate JSON format
            new_vnf, errors = parse_json(new_vnf_json)
            # puts 'vnf: ', new_ns.to_json
            # puts 'new_vnf id', new_vnf['_id'].to_json
            halt 400, errors.to_json if errors

          else
            # Compatibility support for JSON content-type
            # Parses and validates JSON format
            new_vnf, errors = parse_json(request.body.read)
            halt 400, errors.to_json if errors
        end

        # Validate VNF
        # Check if same vendor, Name, Version do already exists in the database
        json_error 400, 'ERROR: VNF Vendor not found' unless new_vnf.has_key?('vendor')
        json_error 400, 'ERROR: VNF Name not found' unless new_vnf.has_key?('name')
        json_error 400, 'ERROR: VNF Version not found' unless new_vnf.has_key?('version')

        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          vnf = Vnf.find_by({ '_id' => params[:id] })
          puts 'VNF is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The VNFD ID #{params[:id]} does not exist"
        end

        # Check if VNF already exists in the catalogue by name, vendor and version
        begin
          vnf = Vnf.find_by({ 'name' => new_vnf['name'], 'vendor' => new_vnf['vendor'], 'version' => new_vnf['version'] })
          json_return 200, 'Duplicated VNF Name, Vendor and Version'
        rescue Mongoid::Errors::DocumentNotFound => e
          # Continue
        end

        # Update to new version
        puts 'Updating...'
        new_vnf['_id'] = SecureRandom.uuid
        vnfd = new_vnf

        # --> Validation disabled
        # Validate VNFD
        #begin
        #	postcurb settings.nsd_validator + '/nsds', nsd.to_json, :content_type => :json
        #rescue => e
        #	logger.error e.response
        #	return e.response.code, e.response.body
        #end

        begin
          new_vnf = Vnf.create!(vnfd)
        rescue Moped::Errors::OperationFailure => e
          json_return 200, 'Duplicated VNF ID' if e.message.include? 'E11000'
        end
        logger.debug "Catalogue: leaving PUT /vnfs/#{params[:id]}\" with VNFD #{new_vnf}"

        response = ''
        case request.content_type
          when 'application/json'
            response = new_vnf.to_json
          when 'application/x-yaml'
            response = json_to_yaml(new_vnf.to_json)
          else
            halt 415
        end
        halt 200, response
      end
    end
    logger.debug "Catalogue: leaving PUT /vnfs/#{params[:id]} with 'No VNF ID specified'"
    json_error 400, 'No VNF ID specified'
  end

  # @method delete_vnfd_sp_vnf
  # @overload delete '/vnfs/?'
  #	Delete a VNF by vendor, name and version
  delete '/vnfs/?' do
    # uri = Addressable::URI.new
    # uri.query_values = params
    # puts 'params', params
    # puts 'query_values', uri.query_values
    logger.info "Catalogue: entered DELETE /vnfs?#{query_string}"

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)
    # puts 'keyed_params', keyed_params

    unless keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      begin
        vnf = Vnf.find_by({ 'vendor' => keyed_params[:vendor], 'name' => keyed_params[:name],
                            'version' => keyed_params[:version] })
        puts 'VNF is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The VNFD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
      logger.debug "Catalogue: leaving DELETE /vnfs?#{query_string}\" with VNFD #{vnf}"
      vnf.destroy
      halt 200, 'OK: VNFD removed'
    end
    logger.debug "Catalogue: leaving DELETE /vnfs?#{query_string} with 'No VNFD Vendor, Name, Version specified'"
    json_error 400, 'No VNFD Vendor, Name, Version specified'
  end

  # @method delete_vnfd_sp_vnf_id
  # @overload delete '/catalogues/vnfs/:id/?'
  #	  Delete a VNF by its ID
  #	  @param :id [Symbol] id VNF ID
  # Delete a VNF by uuid
  delete '/vnfs/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: DELETE /vnfs/#{params[:id]}"
      begin
        vnf = Vnf.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The VNFD ID #{params[:id]} does not exist" unless vnf
      end
      logger.debug "Catalogue: leaving DELETE /vnfs/#{params[:id]}\" with VNFD #{vnf}"
      vnf.destroy
      halt 200, 'OK: VNFD removed'
    end
    logger.debug "Catalogue: leaving DELETE /vnfs/#{params[:id]} with 'No VNFD ID specified'"
    json_error 400, 'No VNFD ID specified'
  end
end

class CatalogueV2 < SonataCatalogue
  ### VNFD API METHODS ###

  # @method get_vnfs
  # @overload get '/catalogues/vnfs/?'
  #	Returns a list of VNFs
  # -> List many descriptors
  get '/vnfs/?' do
    params['page_number'] ||= DEFAULT_PAGE_NUMBER
    params['page_size'] ||= DEFAULT_PAGE_SIZE

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Logger details
    operation = "GET /v2/vnfs?#{query_string}"
    component = __method__.to_s
    time_req_begin = Time.now.utc


    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")


    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')


    # Split keys in meta_data and data
    # Then transform 'string' params Hash into keys
    keyed_params = add_descriptor_level('vnfd', params)

    # Set headers
    case request.content_type
      when 'application/x-yaml'
        headers = { 'Accept' => 'application/x-yaml', 'Content-Type' => 'application/x-yaml' }
      else
        headers = { 'Accept' => 'application/json', 'Content-Type' => 'application/json' }
    end
    headers[:params] = params unless params.empty?

    # Get rid of :page_number and :page_size
    [:page_number, :page_size].each { |k| keyed_params.delete(k) }

    # Check for special case (:version param == last)
    if keyed_params.key?(:'vnfd.version') && keyed_params[:'vnfd.version'] == 'last'
      # Do query for last version -> get_vnfd_vnf_vendor_last_version
      keyed_params.delete(:'vnfd.version')

      vnfs = Vnfd.where((keyed_params)).sort({ 'vnfd.version' => -1 }) #.limit(1).first()
      # vnfs = vnfs.sort({"version" => -1})

      if vnfs && vnfs.size.to_i > 0
        logger.cust_debug(component: component, operation: operation, message: "VNFDs=#{vnfs}")

        vnfs_list = []
        checked_list = []

        vnfs_name_vendor = Pair.new(vnfs.first.vnfd['name'], vnfs.first.vnfd['vendor'])
        checked_list.push(vnfs_name_vendor)
        vnfs_list.push(vnfs.first)

        vnfs.each do |vnfd|
          if (vnfd.vnfd['name'] != vnfs_name_vendor.one) || (vnfd.vnfd['vendor'] != vnfs_name_vendor.two)
            vnfs_name_vendor = Pair.new(vnfd.vnfd['name'], vnfd.vnfd['vendor'])
          end
          vnfs_list.push(vnfd) unless checked_list.any? { |pair| pair.one == vnfs_name_vendor.one &&
              pair.two == vnfs_name_vendor.two }
          checked_list.push(vnfs_name_vendor)
        end
      else
        logger.cust_debug(component: component, operation: operation, message: "No VNFDs were found")
        vnfs_list = []

      end
      vnfs = apply_limit_and_offset(vnfs_list, page_number=params[:page_number], page_size=params[:page_size])

    else
      # Do the query
      keyed_params = parse_keys_dict(:vnfd, keyed_params)
      vnfs = Vnfd.where(keyed_params)
      # Set total count for results
      headers 'Record-Count' => vnfs.count.to_s
      if vnfs && vnfs.size.to_i > 0
        logger.cust_debug(component: component, operation: operation, message: "VNFDs=#{vnfs}")
        # Paginate results
        vnfs = vnfs.paginate(page_number: params[:page_number], page_size: params[:page_size])
      else
        logger.cust_debug(component: component, operation: operation, message: "No VNFDs were found")
      end
    end

    # Transform in unified format
    arr = []
    JSON.parse(vnfs.to_json).each do |desc|
      if desc['platform'] != '5gtango'
        header = desc.delete('header')
        content = desc.delete('vnfd')
        desc['vnfd'] = {header => {'vnfd': content} }
      end
      arr << desc
    end

    logger.cust_info(status: 200, start_stop: 'STOP', message: "Ended at #{Time.now.utc}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

    response = case request.content_type
                 when 'application/json'
                   arr.any? ? arr.to_json : vnfs.to_json
                 else
                   arr.any? ? json_to_yaml(arr.to_json) : json_to_yaml(vnfs.to_json)
               end

    halt 200, {'Content-type' => request.content_type}, response

  end

  # @method get_vnfs_id
  # @overload get '/catalogues/vnfs/:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] id VNF ID
  # Show a VNF by internal ID (uuid)
  get '/vnfs/:id/?' do

    # Logger details
    operation = "GET /v2/vnfs?#{params[:id]}"
    component = __method__.to_s
    time_req_begin = Time.now.utc


    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?

      begin
        vnf = Vnfd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The VNFD ID #{params[:id]} does not exist", component, operation, time_req_begin unless vnf
      end

      logger.cust_info(status: 200, start_stop: 'STOP', message: "Ended at #{Time.now.utc}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

      # Transform descriptor in its initial form
      vnf = transform_descriptor(vnf, type_of_desc='vnfd') if vnf['platform'] == 'osm'


      case request.content_type
        when 'application/json'
          response = vnf.to_json
        else
          response = json_to_yaml(vnf.to_json)
      end
      halt 200, {'Content-type' => request.content_type}, response

    end
    json_error 400, 'No VNFD ID specified', component, operation, time_req_begin
  end

  # @method post_vnfs
  # @overload post '/catalogues/vnfs'
  # Post a VNF in JSON or YAML format
  post '/vnfs' do

    # Logger details
    operation = "POST /v2/vnfs"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Retrieve body request and platform
    body_request = request.body.read
    vnf_body = body_request.split('&platform=')[0]
    body_params = body_request.split('&platform=')[1..-1]
    json_error 400, "Empty body request", component, operation, time_req_begin if body_request.blank?

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a VNFD, the json object sent to API must contain just data inside
        # of the vnfd, without the json field vnfd: before
        vnf, errors = parse_yaml(vnf_body)
        json_error 400, errors, component, operation, time_req_begin if errors

        # Translate from YAML format to JSON format
        new_vnf_json = yaml_to_json(vnf)

        # Validate JSON format
        new_vnf, errors = parse_json(new_vnf_json)
        json_error 400, errors, component, operation, time_req_begin if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_vnf, errors = parse_json(vnf_body)
        json_error 400, errors, component, operation, time_req_begin if errors
    end

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Retrieve platform parameter
    platform = if body_params.count == 1
                 body_params[0].downcase
               else
                 '5gtango'
               end
    if platform == 'osm'
      header, new_vnf = new_vnf.first
      new_vnf = new_vnf.values[0][0]
    end

    # Validate VNF
    json_error 400, 'VNF Vendor not found', component, operation, time_req_begin unless new_vnf.has_key?('vendor')
    json_error 400, 'VNF Name not found', component, operation, time_req_begin unless new_vnf.has_key?('name')
    json_error 400, 'VNF Version not found', component, operation, time_req_begin unless new_vnf.has_key?('version')

    # Comment for file re-usage. Introduce the reference counting of package
    # Check if VNFD already exists in the catalogue by name, vendor and version
    begin
      vnf = Vnfd.find_by({ 'vnfd.name' => new_vnf['name'], 'vnfd.vendor' => new_vnf['vendor'],
                           'vnfd.version' => new_vnf['version'], 'platform' => platform  })
      vnf.update_attributes(pkg_ref: vnf['pkg_ref'] + 1)
      response = ''

      logger.cust_info(status: 200, start_stop: 'STOP',message: "Update reference to #{vnf['pkg_ref']}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

      # Transform descriptor in its initial form
      vnf = transform_descriptor(vnf, type_of_desc='vnfd') if vnf['platform'] == 'osm'

      case request.content_type
        when 'application/json'
          response = vnf.to_json
        else
          response = json_to_yaml(vnf.to_json)
      end

      halt 200, {'Content-type' => request.content_type}, response
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    # Check if VNFD has an ID (it should not) and if it already exists in the catalogue
    begin
      vnf = Vnfd.find_by({ '_id' => new_vnf['_id'] })
      json_error 409, 'Duplicated VNF ID', component, operation, time_req_begin
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    if keyed_params.key?(:username)
      username = keyed_params[:username]
    else
      username = nil
    end

    # Save to DB
    new_vnfd = {}
    new_vnfd['vnfd'] = new_vnf
    # Generate the UUID for the descriptor
    new_vnfd['_id'] = SecureRandom.uuid
    new_vnfd['platform'] = platform
    new_vnfd['header'] = header if platform == 'osm'
    new_vnfd['status'] = 'active'
    new_vnfd['pkg_ref'] = 1
    new_vnfd['signature'] = nil
    new_vnfd['md5'] = checksum new_vnf.to_s
    new_vnfd['username'] = username


    # First, Refresh dictionary about the new entry
    update_entr_dict(new_vnfd, :vnfd)

    begin
      vnf = Vnfd.create!(new_vnfd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated VNF ID', component, operation, time_req_begin if e.message.include? 'E11000'
    end
    logger.cust_debug(component: component, operation: operation, message: 'New VNF has been added')
    logger.cust_info(status: 201, start_stop: 'STOP', message: "Ended at #{Time.now.utc}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

    # Transform descriptor in its initial form
    vnf = transform_descriptor(vnf, type_of_desc='vnfd') if vnf['platform'] == 'osm'

    case request.content_type
      when 'application/json'
        response = vnf.to_json
      else
        response = json_to_yaml(vnf.to_json)
    end
    halt 201, {'Content-type' => request.content_type}, response
  end

  # @method update_vnfs
  # @overload put '/vnfs/?'
  # Update a VNF by vendor, name and version in JSON or YAML format
  ## Catalogue - UPDATE
  put '/vnfs/?' do

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Logger details
    operation = "PUT /v2/vnfs?#{query_string}"
    component = __method__.to_s
    time_req_begin = Time.now.utc


    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')


    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Return if params are empty
    json_error 400, 'Update parameters are null', component, operation, time_req_begin if keyed_params.empty?

    # Retrieve body request and platform
    body_request = request.body.read
    vnf_body = body_request.split('&platform=')[0]
    body_params = body_request.split('&platform=')[1..-1]
    json_error 400, "Empty body request", component, operation, time_req_begin if body_request.blank?

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a VNFD, the json object sent to API must contain just data inside
        # of the vnfd, without the json field vnfd: before
        vnf, errors = parse_yaml(vnf_body)
        json_error 400, errors, component, operation, time_req_begin if errors

        # Translate from YAML format to JSON format
        new_vnf_json = yaml_to_json(vnf)

        # Validate JSON format
        new_vnf, errors = parse_json(new_vnf_json)
        json_error 400, errors, component, operation, time_req_begin if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_vnf, errors = parse_json(vnf_body)
        json_error 400, errors, component, operation, time_req_begin if errors
    end


    # Retrieve platform parameter
    platform = if body_params.count == 1
                 body_params[0].downcase
               else
                 '5gtango'
               end
    if platform == 'osm'
      header, new_vnf = new_vnf.first
      new_vnf = new_vnf.values[0][0]
    end

    # Validate NS
    # Check if mandatory fields Vendor, Name, Version are included
    json_error 400, 'VNF Vendor not found', component, operation, time_req_begin unless new_vnf.has_key?('vendor')
    json_error 400, 'VNF Name not found', component, operation, time_req_begin unless new_vnf.has_key?('name')
    json_error 400, 'VNF Version not found', component, operation, time_req_begin unless new_vnf.has_key?('version')

    # Set headers
    case request.content_type
      when 'application/x-yaml'
        headers = { 'Accept' => 'application/x-yaml', 'Content-Type' => 'application/x-yaml' }
      else
        headers = { 'Accept' => 'application/json', 'Content-Type' => 'application/json' }
    end
    headers[:params] = params unless params.empty?

    # Retrieve stored version
    if keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      json_error 400, 'Update Vendor, Name and Version parameters are null', component, operation, time_req_begin
    else
      begin
        vnf = Vnfd.find_by({ 'vnfd.vendor' => keyed_params[:vendor], 'vnfd.name' => keyed_params[:name],
                            'vnfd.version' => keyed_params[:version] })
        logger.cust_debug(component: component, operation: operation, message: 'VNF is found')
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The VNFD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist", component, operation, time_req_begin
      end
    end
    # Check if VNF already exists in the catalogue by Name, Vendor and Version
    begin
      vnf = Vnfd.find_by({ 'vnfd.name' => new_vnf['name'], 'vnfd.vendor' => new_vnf['vendor'],
                           'vnfd.version' => new_vnf['version'] })
      json_return 200, 'Duplicated VNF Name, Vendor and Version', component, operation, time_req_begin
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    if keyed_params.key?(:username)
      username = keyed_params[:username]
    else
      username = nil
    end

    # Update to new version
    puts 'Updating...'
    new_vnfd = {}
    new_vnfd['_id'] = SecureRandom.uuid # Unique UUIDs per VNFD entries
    new_vnfd['vnfd'] = new_vnf
    new_vnfd['platform'] = platform
    new_vnfd['header'] = header if platform == 'osm'
    new_vnfd['status'] = 'active'
    new_vnfd['pkg_ref'] = 1
    new_vnfd['signature'] = nil
    new_vnfd['md5'] = checksum new_vnf.to_s
    new_vnfd['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_vnfd, :vnfd)

    begin
      new_vnf = Vnf.create!(new_vnfd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated VNF ID', component, operation, time_req_begin if e.message.include? 'E11000'
    end
    logger.cust_debug(component: component, operation: operation, message: "VNFD #{new_vnf}")
    logger.cust_info(status: 201, start_stop: 'STOP', message: "Ended at #{Time.now.utc}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

    # Transform descriptor in its initial form
    new_vnf = transform_descriptor(new_vnf, type_of_desc='vnfd') if new_vnf['platform'] == 'osm'

    case request.content_type
      when 'application/json'
        response = new_vnf.to_json
      else
        response = json_to_yaml(new_vnf.to_json)
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method update_vnfs_id
  # @overload put '/catalogues/vnfs/:id/?'
  #	Update a VNF by its ID in JSON or YAML format
  ## Catalogue - UPDATE
  put '/vnfs/:id/?' do

    # Logger details
    operation = "PUT /v2/vnfs?#{params[:id]}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")


    unless params[:id].nil?

      #Delete key "captures" if present
      params.delete(:captures) if params.key?(:captures)

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)

      # Check for special case (:status param == <new_status>)
      if keyed_params.key?(:status)
        # Do update of Descriptor status -> update_vnf_status
        logger.cust_debug(component: component, operation: operation, message: "/v2/vnfs/#{query_string}")

        # Validate VNF
        # Retrieve stored version
        begin
          vnf = Vnfd.find_by({ '_id' => params[:id] })
          logger.cust_debug(component: component, operation: operation, message: "VNF #{params[:id]} is found")
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This VNFD does not exists', component, operation, time_req_begin
        end

        #Validate new status
        valid_status = %w(active inactive delete)
        if valid_status.include? keyed_params[:status]
          # Update to new status
          begin
            vnf.update_attributes(status: keyed_params[:status])
          rescue Moped::Errors::OperationFailure => e
            json_error 400, 'Operation failed', component, operation, time_req_begin
          end
        else
          json_error 400, "Invalid new status #{keyed_params[:status]}", component, operation, time_req_begin
        end
        json_return 200, "Status updated to {#{query_string}}", component, operation, time_req_begin

      else

        # Return if content-type is invalid
        json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')


        # Retrieve body request and platform
        body_request = request.body.read
        vnf_body = body_request.split('&platform=')[0]
        body_params = body_request.split('&platform=')[1..-1]
        json_error 400, "Empty body request", component, operation, time_req_begin if body_request.blank?

        # Compatibility support for YAML content-type
        case request.content_type
          when 'application/x-yaml'
            # Validate YAML format
            # When updating a VNFD, the json object sent to API must contain just data inside
            # of the vnfd, without the json field vnfd: before
            vnf, errors = parse_yaml(vnf_body)
            json_error 400, errors, component, operation, time_req_begin if errors

            # Translate from YAML format to JSON format
            new_vnf_json = yaml_to_json(vnf)

            # Validate JSON format
            new_vnf, errors = parse_json(new_vnf_json)
            json_error 400, errors, component, operation, time_req_begin if errors

          else
            # Compatibility support for JSON content-type
            # Parses and validates JSON format
            new_vnf, errors = parse_json(vnf_body)
            json_error 400, errors, component, operation, time_req_begin if errors
        end

        # Retrieve platform parameter
        platform = if body_params.count == 1
                     body_params[0].downcase
                   else
                     '5gtango'
                   end
        if platform == 'osm'
          header, new_vnf = new_vnf.first
          new_vnf = new_vnf.values[0][0]
        end

        # Validate VNF
        # Check if mandatory fields Vendor, Name, Version are included
        json_error 400, 'VNF Vendor not found', component, operation, time_req_begin unless new_vnf.has_key?('vendor')
        json_error 400, 'VNF Name not found', component, operation, time_req_begin unless new_vnf.has_key?('name')
        json_error 400, 'VNF Version not found', component, operation, time_req_begin unless new_vnf.has_key?('version')

        # Retrieve stored version
        begin
          vnf = Vnfd.find_by({ '_id' => params[:id] })
          logger.cust_debug(component: component, operation: operation, message: "VNF #{params[:id]} is found")
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The VNFD ID #{params[:id]} does not exist", component, operation, time_req_begin
        end

        # Check if VNF already exists in the catalogue by name, vendor and version
        begin
          vnf = Vnfd.find_by({ 'vnfd.name' => new_vnf['name'], 'vnfd.vendor' => new_vnf['vendor'],
                               'vnfd.version' => new_vnf['version'] })
          json_return 200, 'Duplicated VNF Name, Vendor and Version', component, operation, time_req_begin
        rescue Mongoid::Errors::DocumentNotFound => e
          # Continue
        end

        if keyed_params.key?(:username)
          username = keyed_params[:username]
        else
          username = nil
        end

        # Update to new version
        puts 'Updating...'
        new_vnfd = {}
        new_vnfd['_id'] = SecureRandom.uuid # Unique UUIDs per VNFD entries
        new_vnfd['vnfd'] = new_vnf
        new_vnfd['status'] = 'active'
        new_vnfd['platform'] = platform
        new_vnfd['header'] = header if platform == 'osm'
        new_vnfd['pkg_ref'] = 1
        new_vnfd['signature'] = nil
        new_vnfd['md5'] = checksum new_vnf.to_s
        new_vnfd['username'] = username

        # First, Refresh dictionary about the new entry
        update_entr_dict(new_vnfd, :vnfd)

        begin
          new_vnf = Vnfd.create!(new_vnfd)
        rescue Moped::Errors::OperationFailure => e
          json_return 200, 'Duplicated VNF ID', component, operation, time_req_begin if e.message.include? 'E11000'
        end
        logger.cust_debug(component: component, operation: operation, message: "VNFD #{new_vnf}")
        logger.cust_info(status: 201, message: "Ended at #{Time.now.utc}", start_stop: 'STOP', component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

        # Transform descriptor in its initial form
        new_vnf = transform_descriptor(new_vnf, type_of_desc='vnfd') if new_vnf['platform'] == 'osm'

        case request.content_type
          when 'application/json'
            response = new_vnf.to_json
          else
            response = json_to_yaml(new_vnf.to_json)
        end

        halt 200, {'Content-type' => request.content_type}, response
      end
    end
    logger.cust_debug(component: component, operation: operation, message: "No VNF ID specified")
    json_error 400, 'No VNF ID specified', component, operation, time_req_begin
  end

  # @method delete_vnfd_sp_vnf
  # @overload delete '/vnfs/?'
  #	Delete a VNF by vendor, name and version
  delete '/vnfs/?' do

    # Logger details
    operation = "DELETE /v2/vnfs?#{query_string}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    unless keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      begin
        vnf = Vnfd.find_by({ 'vnfd.vendor' => keyed_params[:vendor], 'vnfd.name' => keyed_params[:name],
                            'vnfd.version' => keyed_params[:version] })
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The VNFD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist", component, operation, time_req_begin
      end

      logger.cust_debug(component: component, operation: operation, message: "VNFD found #{vnf}")

      if vnf['pkg_ref'] == 1
        # Delete entry in dict mapping
        del_ent_dict(vnf, :vnfd)
        vnf.destroy
        json_return 200, 'VNFD removed', component, operation, time_req_begin
      else
        vnf.update_attributes(pkg_ref: vnf['pkg_ref'] - 1)
        json_return 200, "VNFD referenced => #{vnf['pkg_ref']}", component, operation, time_req_begin
      end

    end
    logger.cust_debug(component: component, operation: operation, message: "No VNFD Vendor, Name, Version specified")
    json_error 400, 'No VNFD Vendor, Name, Version specified', component, operation, time_req_begin
  end

  # @method delete_vnfd_sp_vnf_id
  # @overload delete '/catalogues/vnfs/:id/?'
  #	  Delete a VNF by its ID
  #	  @param :id [Symbol] id VNF ID
  # Delete a VNF by uuid
  delete '/vnfs/:id/?' do

    # Logger details
    operation = "DELETE /v2/vnfs?#{params[:id]}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    unless params[:id].nil?
      begin
        vnf = Vnfd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The VNFD ID #{params[:id]} does not exist", component, operation, time_req_begin unless vnf
      end
      logger.cust_debug(component: component, operation: operation, message: "VNFD found #{vnf}")

      if vnf['pkg_ref'] == 1
        # Referenced only once. Delete in this case
        # Delete entry in dict mapping
        del_ent_dict(vnf, :vnfd)
        vnf.destroy
        json_return 200, 'VNFD removed', component, operation, time_req_begin
      else
        # Referenced above once. Decrease counter
        vnf.update_attributes(pkg_ref: vnf['pkg_ref'] - 1)
        json_return 200, "VNFD referenced => #{vnf['pkg_ref']}", component, operation, time_req_begin
      end

    end
    logger.cust_debug(component: component, operation: operation, message: "No VNFD ID specified")
    json_error 400, 'No VNFD ID specified', component, operation, time_req_begin
  end
end
