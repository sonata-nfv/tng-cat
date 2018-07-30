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

class CatalogueV2 < SonataCatalogue
  ### NSD API METHODS ###

  # @method get_nssSS
  # @overload get '/catalogues/network-services/?'
  #	Returns a list of NSs
  # -> List many descriptors
  get '/network-services/?' do
    params['page_number'] ||= DEFAULT_PAGE_NUMBER
    params['page_size'] ||= DEFAULT_PAGE_SIZE
    logger.info "Catalogue: entered GET /v2/network-services?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Split keys in meta_data and data
    # Then transform 'string' params Hash into keys
    keyed_params = add_descriptor_level('nsd', params)

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
    if keyed_params.key?(:'nsd.version') && keyed_params[:'nsd.version'] == 'last'
      # Do query for last version -> get_nsd_ns_vendor_last_version
      keyed_params.delete(:'nsd.version')

      nss = Nsd.where((keyed_params)).sort({ 'nsd.version' => -1 }) #.limit(1).first()
      logger.info "Catalogue: NSDs=#{nss}"
      nss = nss.sort({"version" => -1})

      if nss && nss.size.to_i > 0
        logger.info "Catalogue: leaving GET /v2/network-services?#{query_string} with #{nss}"

        nss_list = []
        checked_list = []

        nss_name_vendor = Pair.new(nss.first.nsd['name'], nss.first.nsd['vendor'])
        checked_list.push(nss_name_vendor)
        nss_list.push(nss.first)

        nss.each do |nsd|
          if (nsd.nsd['name'] != nss_name_vendor.one) || (nsd.nsd['vendor'] != nss_name_vendor.two)
            nss_name_vendor = Pair.new(nsd.nsd['name'], nsd.nsd['vendor'])
          end
          nss_list.push(nsd) unless checked_list.any? { |pair| pair.one == nss_name_vendor.one &&
              pair.two == nss_name_vendor.two }
          checked_list.push(nss_name_vendor)
        end
      else
        logger.info "Catalogue: leaving GET /v2/network-services?#{query_string} with 'No NSDs were found'"
        nss_list = []
      end
      nss = apply_limit_and_offset(nss_list, page_number=params[:page_number],
                                   page_size=params[:page_size])

    else
      # Do the query
      keyed_params = parse_keys_dict(:nsd, keyed_params)
      nss = Nsd.where(keyed_params)

      # Set total count for results
      headers 'Record-Count' => nss.count.to_s
      logger.info "Catalogue: NSDs=#{nss}"
      if nss && nss.size.to_i > 0
        logger.info "Catalogue: leaving GET /v2/network-services?#{query_string} with #{nss}"

        # Paginate results
        nss = nss.paginate(page_number: params[:page_number], page_size: params[:page_size])
      else
        logger.info "Catalogue: leaving GET /v2/network-services?#{query_string} with 'No NSDs were found'"
      end
    end

    response = resp_json_yaml(nss)

    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method get_ns_sp_ns_id
  # @overload get '/catalogues/network-services/:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] unique identifier
  # Show a NS by internal ID (uuid)
  get '/network-services/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: GET /v2/network-services/#{params[:id]}"

      begin
        ns = Nsd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The NSD ID #{params[:id]} does not exist" unless ns
      end
      logger.debug "Catalogue: leaving GET /v2/network-services/#{params[:id]}\" with NSD #{ns}"

      response = resp_json_yaml(ns)

      halt 200, {'Content-type' => request.content_type}, response

    end
    logger.debug "Catalogue: leaving GET /v2/network-services/#{params[:id]} with 'No NSD ID specified'"
    json_error 400, 'No NSD ID specified'
  end

  # @method post_nss
  # @overload post '/catalogues/network-services'
  # Post a NS in JSON or YAML format
  post '/network-services' do

    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Compatibility support for YAML content-type
    new_ns = validate_json_yaml

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Validate NS
    json_error 400, 'ERROR: NS Vendor not found' unless new_ns.has_key?('vendor')
    json_error 400, 'ERROR: NS Name not found' unless new_ns.has_key?('name')
    json_error 400, 'ERROR: NS Version not found' unless new_ns.has_key?('version')

    # Check if NS already exists in the catalogue by name, vendor and version
    begin
      ns = Nsd.find_by({ 'nsd.name' => new_ns['name'], 'nsd.vendor' => new_ns['vendor'],
                         'nsd.version' => new_ns['version'] })
      halt 409, "Duplicate with NSD ID => #{ns['_id']}"
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    # Check if NSD has an ID (it should not) and if it already exists in the catalogue
    begin
      ns = Nsd.find_by({ '_id' => new_ns['_id'] })
      halt 409, 'Duplicated NS ID'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    if keyed_params.key?(:username)
      username = keyed_params[:username]
    else
      username = nil
    end

    # Save to DB
    new_nsd = {}
    new_nsd['nsd'] = new_ns
    new_nsd['_id'] = SecureRandom.uuid # Generate the UUID for the descriptor
    new_nsd['status'] = 'active'
    new_nsd['signature'] = nil # Signature will be supported
    new_nsd['md5'] = checksum new_ns.to_s
    new_nsd['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_nsd, :nsd)

    # Then, create descriptor
    begin
      ns = Nsd.create!(new_nsd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated NS ID' if e.message.include? 'E11000'
    end

    puts 'New NS has been added'

    response = resp_json_yaml(ns)

    halt 201, {'Content-type' => request.content_type}, response
  end

  # @method update_nss
  # @overload put '/catalogues/network-services/?'
  # Update a NS by vendor, name and version in JSON or YAML format
  ## Catalogue - UPDATE
  put '/network-services/?' do
    logger.info "Catalogue: entered PUT /v2/network-services?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Return 400 if params are empty
    json_error 400, 'Update parameters are null' if keyed_params.empty?

    # Compatibility support for YAML content-type
    new_ns = validate_json_yaml

    # Validate NS
    # Check if mandatory fields Vendor, Name, Version are included
    json_error 400, 'ERROR: NS Vendor not found' unless new_ns.has_key?('vendor')
    json_error 400, 'ERROR: NS Name not found' unless new_ns.has_key?('name')
    json_error 400, 'ERROR: NS Version not found' unless new_ns.has_key?('version')

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
        ns = Nsd.find_by({ 'nsd.vendor' => keyed_params[:vendor], 'nsd.name' => keyed_params[:name],
                          'nsd.version' => keyed_params[:version] })
        puts 'NS is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The NSD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
    end

    # Check if NS already exists in the catalogue by Name, Vendor and Version
    begin
      ns = Nsd.find_by({ 'nsd.name' => new_ns['name'], 'nsd.vendor' => new_ns['vendor'],
                         'nsd.version' => new_ns['version'] })
      json_return 200, 'Duplicated NS Name, Vendor and Version'
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
    new_nsd = {}
    new_nsd['_id'] = SecureRandom.uuid # Unique UUIDs per NSD entries
    new_nsd['nsd'] = new_ns
    new_nsd['status'] = 'active'
    new_nsd['signature'] = nil
    new_nsd['md5'] = checksum new_ns.to_s
    new_nsd['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_nsd, :nsd)

    # Then, create descriptor
    begin
      new_ns = Nsd.create!(new_nsd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated NS ID' if e.message.include? 'E11000'
    end
    logger.debug "Catalogue: leaving PUT /v2/network-services?#{query_string}\" with NSD #{new_ns}"

    response = resp_json_yaml(new_ns)

    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method update_nss_id
  # @overload put '/catalogues/network-services/:id/?'
  # Update a NS in JSON or YAML format
  ## Catalogue - UPDATE
  put '/network-services/:id/?' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    unless params[:id].nil?
      logger.debug "Catalogue: PUT /v2/network-services/#{params[:id]}"

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)

      # Check for special case (:status param == <new_status>)
      if keyed_params.key?(:status)
        # Do update of Descriptor status -> update_ns_status
        logger.info "Catalogue: entered PUT /v2/network-services/#{query_string}"

        # Validate NS
        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          ns = Nsd.find_by({ '_id' => params[:id] })
          puts 'NS is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This NSD does not exists'
        end

        # Validate new status
        valid_status = %w(active inactive delete)
        if valid_status.include? keyed_params[:status]
          # Update to new status
          begin
            ns.update_attributes(status: keyed_params[:status])
          rescue Moped::Errors::OperationFailure => e
            json_error 400, 'ERROR: Operation failed'
          end
        else
          json_error 400, "Invalid new status #{keyed_params[:status]}"
        end
        halt 200, "Status updated to {#{query_string}}"

      else
        # Compatibility support for YAML content-type
        new_ns = validate_json_yaml

        # Validate NS
        # Check if mandatory fields Vendor, Name, Version are included
        json_error 400, 'ERROR: NS Vendor not found' unless new_ns.has_key?('vendor')
        json_error 400, 'ERROR: NS Name not found' unless new_ns.has_key?('name')
        json_error 400, 'ERROR: NS Version not found' unless new_ns.has_key?('version')

        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          ns = Nsd.find_by({ '_id' => params[:id] })
          puts 'NS is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The NSD ID #{params[:id]} does not exist"
        end

        # Check if NS already exists in the catalogue by name, vendor and version
        begin
          ns = Nsd.find_by({ 'nsd.name' => new_ns['name'], 'nsd.vendor' => new_ns['vendor'],
                             'nsd.version' => new_ns['version'] })
          json_return 200, 'Duplicated NS Name, Vendor and Version'
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
        new_nsd = {}
        new_nsd['_id'] = SecureRandom.uuid # Unique UUIDs per NSD entries
        new_nsd['nsd'] = new_ns
        new_nsd['status'] = 'active'
        new_nsd['signature'] = nil
        new_nsd['md5'] = checksum new_ns.to_s
        new_nsd['username'] = username

        # First, Refresh dictionary about the new entry
        update_entr_dict(new_nsd, :nsd)

        # Then, create descriptor
        begin
          new_ns = Nsd.create!(new_nsd)
        rescue Moped::Errors::OperationFailure => e
          json_return 200, 'Duplicated NS ID' if e.message.include? 'E11000'
        end
        logger.debug "Catalogue: leaving PUT /v2/network-services/#{params[:id]}\" with NSD #{new_ns}"

        response = resp_json_yaml(new_ns)

        halt 200, {'Content-type' => request.content_type}, response
      end
    end
    logger.debug "Catalogue: leaving PUT /v2/network-services/#{params[:id]} with 'No NSD ID specified'"
    json_error 400, 'No NSD ID specified'
  end

  # @method delete_nsd_sp_ns
  # @overload delete '/network-services/?'
  #	Delete a NS by vendor, name and version
  delete '/network-services/?' do

    logger.info "Catalogue: entered DELETE /v2/network-services?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    unless keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      begin
        ns = Nsd.find_by({ 'nsd.vendor' => keyed_params[:vendor], 'nsd.name' => keyed_params[:name],
                          'nsd.version' => keyed_params[:version]} )
        puts 'NS is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The NSD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end

      logger.debug "Catalogue: leaving DELETE /v2/network-services?#{query_string}\" with NSD #{ns}"
      ns.destroy

      # Delete entry in dict mapping
      del_ent_dict(ns, :nsd)
      halt 200, 'OK: NSD removed'
    end

    logger.debug "Catalogue: leaving DELETE /v2/network-services?#{query_string} with 'No NSD Vendor, Name, Version specified'"
    json_error 400, 'No NSD Vendor, Name, Version specified'
  end

  # @method delete_nsd_sp_ns_id
  # @overload delete '/catalogues/network-service/:id/?'
  #	  Delete a NS by its ID
  #	  @param :id [Symbol] unique identifier
  # Delete a NS by uuid
  delete '/network-services/:id/?' do

    unless params[:id].nil?
      logger.debug "Catalogue: DELETE /v2/network-services/#{params[:id]}"
      begin
        ns = Nsd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The NSD ID #{params[:id]} does not exist" unless ns
      end

      logger.debug "Catalogue: leaving DELETE /v2/network-services/#{params[:id]}\" with NSD #{ns}"
      ns.destroy

      # Delete entry in dict mapping
      del_ent_dict(ns, :nsd)
      halt 200, 'OK: NSD removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/network-services/#{params[:id]} with 'No NSD ID specified'"
    json_error 400, 'No NSD ID specified'
  end
end
