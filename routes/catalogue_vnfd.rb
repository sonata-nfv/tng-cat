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
  ### VNFD API METHODS ###

  # @method get_vnfs
  # @overload get '/catalogues/vnfs/?'
  #	Returns a list of VNFs
  # -> List many descriptors
  get '/vnfs/?' do
    params['page_number'] ||= DEFAULT_PAGE_NUMBER
    params['page_size'] ||= DEFAULT_PAGE_SIZE
    logger.info "Catalogue: entered GET /v2/vnfs?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

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
      logger.info "Catalogue: VNFDs=#{vnfs}"
      # vnfs = vnfs.sort({"version" => -1})

      if vnfs && vnfs.size.to_i > 0
        logger.info "Catalogue: leaving GET /v2/vnfs?#{query_string} with #{vnfs}"

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
        logger.info "Catalogue: leaving GET /v2/vnfs?#{query_string} with 'No VNFDs were found'"
        vnfs_list = []

      end
      vnfs = apply_limit_and_offset(vnfs_list, page_number=params[:page_number], page_size=params[:page_size])

    else
      # Do the query
      keyed_params = parse_keys_dict(:vnfd, keyed_params)
      vnfs = Vnfd.where(keyed_params)
      # Set total count for results
      headers 'Record-Count' => vnfs.count.to_s
      logger.info "Catalogue: VNFDs=#{vnfs}"
      if vnfs && vnfs.size.to_i > 0
        logger.info "Catalogue: leaving GET /v2/vnfs?#{query_string} with #{vnfs}"
        # Paginate results
        vnfs = vnfs.paginate(page_number: params[:page_number], page_size: params[:page_size])
      else
        logger.info "Catalogue: leaving GET /v2/vnfs?#{query_string} with 'No VNFDs were found'"
      end
    end

    response = resp_json_yaml(vnfs)

    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method get_vnfs_id
  # @overload get '/catalogues/vnfs/:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] id VNF ID
  # Show a VNF by internal ID (uuid)
  get '/vnfs/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: GET /v2/vnfs/#{params[:id]}"

      begin
        vnf = Vnfd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The VNFD ID #{params[:id]} does not exist" unless vnf
      end
      logger.debug "Catalogue: leaving GET /v2/vnfs/#{params[:id]}\" with VNFD #{vnf}"

      response = resp_json_yaml(vnf)

      halt 200, {'Content-type' => request.content_type}, response

    end
    logger.debug "Catalogue: leaving GET /v2/vnfs/#{params[:id]} with 'No VNFD ID specified'"
    json_error 400, 'No VNFD ID specified'
  end

  # @method post_vnfs
  # @overload post '/catalogues/vnfs'
  # Post a VNF in JSON or YAML format
  post '/vnfs' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    new_vnf = validate_json_yaml

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Validate VNF
    json_error 400, 'ERROR: VNF Vendor not found' unless new_vnf.has_key?('vendor')
    json_error 400, 'ERROR: VNF Name not found' unless new_vnf.has_key?('name')
    json_error 400, 'ERROR: VNF Version not found' unless new_vnf.has_key?('version')

    # Check if VNFD already exists in the catalogue by name, vendor and version
    begin
      vnf = Vnfd.find_by({ 'vnfd.name' => new_vnf['name'], 'vnfd.vendor' => new_vnf['vendor'],
                           'vnfd.version' => new_vnf['version'] })
      halt 409, "Duplicated VNF with ID => #{vnf['_id']}"
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end
    # Check if VNFD has an ID (it should not) and if it already exists in the catalogue
    begin
      vnf = Vnfd.find_by({ '_id' => new_vnf['_id'] })
      halt 409, 'Duplicated VNF ID'
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
    new_vnfd['status'] = 'active'
    new_vnfd['signature'] = nil
    new_vnfd['md5'] = checksum new_vnf.to_s
    new_vnfd['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_vnfd, :vnfd)

    begin
      vnf = Vnfd.create!(new_vnfd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated VNF ID' if e.message.include? 'E11000'
    end

    puts 'New VNF has been added'

    response = resp_json_yaml(vnf)

    halt 201, {'Content-type' => request.content_type}, response
  end

  # @method update_vnfs
  # @overload put '/vnfs/?'
  # Update a VNF by vendor, name and version in JSON or YAML format
  ## Catalogue - UPDATE
  put '/vnfs/?' do
    logger.info "Catalogue: entered PUT /v2/vnfs?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Return if params are empty
    json_error 400, 'Update parameters are null' if keyed_params.empty?

    # Compatibility support for YAML content-type
    new_vnf = validate_json_yaml

    # Validate NS
    # Check if mandatory fields Vendor, Name, Version are included
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
        vnf = Vnfd.find_by({ 'vnfd.vendor' => keyed_params[:vendor], 'vnfd.name' => keyed_params[:name],
                            'vnfd.version' => keyed_params[:version] })
        puts 'VNF is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The VNFD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
    end
    # Check if VNF already exists in the catalogue by Name, Vendor and Version
    begin
      vnf = Vnfd.find_by({ 'vnfd.name' => new_vnf['name'], 'vnfd.vendor' => new_vnf['vendor'],
                           'vnfd.version' => new_vnf['version'] })
      json_return 200, 'Duplicated VNF Name, Vendor and Version'
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
    new_vnfd['signature'] = nil
    new_vnfd['md5'] = checksum new_vnf.to_s
    new_vnfd['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_vnfd, :vnfd)

    begin
      new_vnf = Vnf.create!(new_vnfd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated VNF ID' if e.message.include? 'E11000'
    end
    logger.debug "Catalogue: leaving PUT /v2/vnfs?#{query_string}\" with VNFD #{new_vnf}"

    response = resp_json_yaml(new_vnf)

    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method update_vnfs_id
  # @overload put '/catalogues/vnfs/:id/?'
  #	Update a VNF by its ID in JSON or YAML format
  ## Catalogue - UPDATE
  put '/vnfs/:id/?' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?
      logger.debug "Catalogue: PUT /v2/vnfs/#{params[:id]}"

      #Delete key "captures" if present
      params.delete(:captures) if params.key?(:captures)

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)

      # Check for special case (:status param == <new_status>)
      if keyed_params.key?(:status)
        # Do update of Descriptor status -> update_vnf_status
        logger.info "Catalogue: entered PUT /v2/vnfs/#{query_string}"

        # Validate VNF
        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          vnf = Vnfd.find_by({ '_id' => params[:id] })
          puts 'VNF is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This VNFD does not exists'
        end

        #Validate new status
        valid_status = %w(active inactive delete)
        if valid_status.include? keyed_params[:status]
          # Update to new status
          begin
            vnf.update_attributes(status: keyed_params[:status])
          rescue Moped::Errors::OperationFailure => e
            json_error 400, 'ERROR: Operation failed'
          end
        else
          json_error 400, "Invalid new status #{keyed_params[:status]}"
        end
        halt 200, "Status updated to {#{query_string}}"

      else
        # Compatibility support for YAML content-type
        new_vnf = validate_json_yaml

        # Validate VNF
        # Check if mandatory fields Vendor, Name, Version are included
        json_error 400, 'ERROR: VNF Vendor not found' unless new_vnf.has_key?('vendor')
        json_error 400, 'ERROR: VNF Name not found' unless new_vnf.has_key?('name')
        json_error 400, 'ERROR: VNF Version not found' unless new_vnf.has_key?('version')

        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          vnf = Vnfd.find_by({ '_id' => params[:id] })
          puts 'VNF is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The VNFD ID #{params[:id]} does not exist"
        end

        # Check if VNF already exists in the catalogue by name, vendor and version
        begin
          vnf = Vnfd.find_by({ 'vnfd.name' => new_vnf['name'], 'vnfd.vendor' => new_vnf['vendor'],
                               'vnfd.version' => new_vnf['version'] })
          json_return 200, 'Duplicated VNF Name, Vendor and Version'
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
        new_vnfd['signature'] = nil
        new_vnfd['md5'] = checksum new_vnf.to_s
        new_vnfd['username'] = username

        # First, Refresh dictionary about the new entry
        update_entr_dict(new_vnfd, :vnfd)

        begin
          new_vnf = Vnfd.create!(new_vnfd)
        rescue Moped::Errors::OperationFailure => e
          json_return 200, 'Duplicated VNF ID' if e.message.include? 'E11000'
        end
        logger.debug "Catalogue: leaving PUT /v2/vnfs/#{params[:id]}\" with VNFD #{new_vnf}"

        response = resp_json_yaml(new_vnf)

        halt 200, {'Content-type' => request.content_type}, response
      end
    end
    logger.debug "Catalogue: leaving PUT /v2/vnfs/#{params[:id]} with 'No VNF ID specified'"
    json_error 400, 'No VNF ID specified'
  end

  # @method delete_vnfd_sp_vnf
  # @overload delete '/vnfs/?'
  #	Delete a VNF by vendor, name and version
  delete '/vnfs/?' do
    logger.info "Catalogue: entered DELETE /v2/vnfs?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    unless keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      begin
        vnf = Vnfd.find_by({ 'vnfd.vendor' => keyed_params[:vendor], 'vnfd.name' => keyed_params[:name],
                            'vnfd.version' => keyed_params[:version] })
        puts 'VNF is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The VNFD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
      logger.debug "Catalogue: leaving DELETE /v2/vnfs?#{query_string}\" with VNFD #{vnf}"
      # Delete entry in dict mapping
      del_ent_dict(vnf, :vnfd)
      vnf.destroy
      halt 200, 'OK: VNFD removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/vnfs?#{query_string} with 'No VNFD Vendor, Name, Version specified'"
    json_error 400, 'No VNFD Vendor, Name, Version specified'
  end

  # @method delete_vnfd_sp_vnf_id
  # @overload delete '/catalogues/vnfs/:id/?'
  #	  Delete a VNF by its ID
  #	  @param :id [Symbol] id VNF ID
  # Delete a VNF by uuid
  delete '/vnfs/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: DELETE /v2/vnfs/#{params[:id]}"
      begin
        vnf = Vnfd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The VNFD ID #{params[:id]} does not exist" unless vnf
      end
      logger.debug "Catalogue: leaving DELETE /v2/vnfs/#{params[:id]}\" with VNFD #{vnf}"
      # Delete entry in dict mapping
      del_ent_dict(vnf, :vnfd)
      vnf.destroy
      halt 200, 'OK: VNFD removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/vnfs/#{params[:id]} with 'No VNFD ID specified'"
    json_error 400, 'No VNFD ID specified'
  end
end
