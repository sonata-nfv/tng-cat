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
  ### NST API METHODS ###

  # @method get_nsts
  # @overload get '/catalogues/nsts/?'
  #	Returns a list of NSTs
  # -> List many descriptors
  get '/nsts/?' do
    params['offset'] ||= DEFAULT_OFFSET
    params['limit'] ||= DEFAULT_LIMIT
    logger.info "Catalogue: entered GET /v2/nsts?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Split keys in meta_data and data
    # Then transform 'string' params Hash into keys
    keyed_params = add_descriptor_level('nstd', params)

    # Set headers
    case request.content_type
      when 'application/x-yaml'
        headers = { 'Accept' => 'application/x-yaml', 'Content-Type' => 'application/x-yaml' }
      else
        headers = { 'Accept' => 'application/json', 'Content-Type' => 'application/json' }
    end
    headers[:params] = params unless params.empty?

    # Get rid of :offset and :limit
    [:offset, :limit].each { |k| keyed_params.delete(k) }

    # Check for special case (:version param == last)
    if keyed_params.key?(:'nstd.version') && keyed_params[:'nstd.version'] == 'last'
      # Do query for last version -> get_nstd_nst_vendor_last_version
      keyed_params.delete(:'nstd.version')

      nsts = Nstd.where((keyed_params)).sort({ 'nstd.version' => -1 }) #.limit(1).first()
      logger.info "Catalogue: NSTs=#{nsts}"

      if nsts && nsts.size.to_i > 0
        logger.info "Catalogue: leaving GET /v2/nsts?#{query_string} with #{nsts}"

        nsts_list = []
        checked_list = []

        nsts_name_vendor = Pair.new(nsts.first.nstd['name'], nsts.first.nstd['vendor'])
        checked_list.push(nsts_name_vendor)
        nsts_list.push(nsts.first)

        nsts.each do |nstd|
          if (nstd.nstd['name'] != nsts_name_vendor.one) || (nstd.nstd['vendor'] != nsts_name_vendor.two)
            nsts_name_vendor = Pair.new(nstd.nstd['name'], nstd.nstd['vendor'])
          end
          nsts_list.push(nstd) unless checked_list.any? { |pair| pair.one == nsts_name_vendor.one &&
              pair.two == nsts_name_vendor.two }
          checked_list.push(nsts_name_vendor)
        end
      else
        logger.info "Catalogue: leaving GET /v2/nsts?#{query_string} with 'No NSTs were found'"
        nsts_list = []

      end
      nsts = apply_limit_and_offset(nsts_list, offset=params[:offset], limit=params[:limit])

    else
      # Do the query
      nsts = Nstd.where(keyed_params)
      # Set total count for results
      headers 'Record-Count' => nsts.count.to_s
      logger.info "Catalogue: NSTs=#{nsts}"
      if nsts && nsts.size.to_i > 0
        logger.info "Catalogue: leaving GET /v2/nsts?#{query_string} with #{nsts}"
        # Paginate results
        nsts = nsts.paginate(offset: params[:offset], limit: params[:limit])
      else
        logger.info "Catalogue: leaving GET /v2/nsts?#{query_string} with 'No NSTs were found'"
      end
    end

    response = ''
    case request.content_type
      when 'application/json'
        response = nsts.to_json
      when 'application/x-yaml'
        response = json_to_yaml(nsts.to_json)
      else
        halt 415
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method get_nsts_id
  # @overload get '/catalogues/nsts/:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] id NST ID
  # Show a NST by internal ID (uuid)
  get '/nsts/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: GET /v2/nsts/#{params[:id]}"

      begin
        nst = Nstd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The NST ID #{params[:id]} does not exist" unless nst
      end
      logger.debug "Catalogue: leaving GET /v2/nsts/#{params[:id]}\" with NST #{nst}"

      response = ''
      case request.content_type
        when 'application/json'
          response = nst.to_json
        when 'application/x-yaml'
          response = json_to_yaml(nst.to_json)
        else
          halt 415
      end
      halt 200, {'Content-type' => request.content_type}, response

    end
    logger.debug "Catalogue: leaving GET /v2/nsts/#{params[:id]} with 'No NST ID specified'"
    json_error 400, 'No NST ID specified'
  end

  # @method post_nsts
  # @overload post '/catalogues/nsts'
  # Post a NST in JSON or YAML format
  post '/nsts' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a NST, the json object sent to API must contain just data inside
        # of the nst, without the json field nst: before
        nst, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_nst_json = yaml_to_json(nst)

        # Validate JSON format
        new_nst, errors = parse_json(new_nst_json)
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_nst, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Validate NST
    json_error 400, 'ERROR: NST Vendor not found' unless new_nst.has_key?('vendor')
    json_error 400, 'ERROR: NST Name not found' unless new_nst.has_key?('name')
    json_error 400, 'ERROR: NST Version not found' unless new_nst.has_key?('version')

    # Check if NST already exists in the catalogue by name, vendor and version
    begin
      nst = Nstd.find_by({ 'nstd.name' => new_nst['name'], 'nstd.vendor' => new_nst['vendor'],
                           'nstd.version' => new_nst['version'] })
      json_return 200, 'Duplicated NST Name, Vendor and Version'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end
    # Check if NST has an ID (it should not) and if it already exists in the catalogue
    begin
      nst = Nstd.find_by({ '_id' => new_nst['_id'] })
      json_return 200, 'Duplicated NST ID'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    if keyed_params.key?(:username)
      username = keyed_params[:username]
    else
      username = nil
    end

    # Save to DB
    begin
      new_nstd = {}
      new_nstd['nstd'] = new_nst
      # Generate the UUID for the descriptor
      new_nstd['_id'] = SecureRandom.uuid
      new_nstd['status'] = 'active'
      new_nstd['signature'] = nil
      new_nstd['md5'] = checksum new_nst.to_s
      new_nstd['username'] = username
      nst = Nstd.create!(new_nstd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated NST ID' if e.message.include? 'E11000'
    end

    puts 'New NST has been added'
    response = ''
    case request.content_type
      when 'application/json'
        response = nst.to_json
      when 'application/x-yaml'
        response = json_to_yaml(nst.to_json)
      else
        halt 415
    end
    halt 201, {'Content-type' => request.content_type}, response
  end

  # @method update_nsts
  # @overload put '/nsts/?'
  # Update a NST by vendor, name and version in JSON or YAML format
  ## Catalogue - UPDATE
  put '/nsts/?' do
    logger.info "Catalogue: entered PUT /v2/nsts?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Return if params are empty
    json_error 400, 'Update parameters are null' if keyed_params.empty?

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a NST, the json object sent to API must contain just data inside
        # of the nstd, without the json field nstd: before
        nst, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_nst_json = yaml_to_json(nst)

        # Validate JSON format
        new_nst, errors = parse_json(new_nst_json)
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_nst, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    # Validate NS
    # Check if mandatory fields Vendor, Name, Version are included
    json_error 400, 'ERROR: NST Vendor not found' unless new_nst.has_key?('vendor')
    json_error 400, 'ERROR: NST Name not found' unless new_nst.has_key?('name')
    json_error 400, 'ERROR: NST Version not found' unless new_nst.has_key?('version')

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
        nst = Nstd.find_by({ 'nstd.vendor' => keyed_params[:vendor], 'nstd.name' => keyed_params[:name],
                            'nstd.version' => keyed_params[:version] })
        puts 'NST is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The NST Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
    end
    # Check if NST already exists in the catalogue by Name, Vendor and Version
    begin
      nst = Nstd.find_by({ 'nstd.name' => new_nst['name'], 'nstd.vendor' => new_nst['vendor'],
                           'nstd.version' => new_nst['version'] })
      json_return 200, 'Duplicated NST Name, Vendor and Version'
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
    new_nstd = {}
    new_nstd['_id'] = SecureRandom.uuid # Unique UUIDs per NST entries
    new_nstd['nstd'] = new_nst
    new_nstd['status'] = 'active'
    new_nstd['signature'] = nil
    new_nstd['md5'] = checksum new_nst.to_s
    new_nstd['username'] = username

    begin
      new_nst = Nstd.create!(new_nstd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated NST ID' if e.message.include? 'E11000'
    end
    logger.debug "Catalogue: leaving PUT /v2/nsts?#{query_string}\" with NST #{new_nst}"

    response = ''
    case request.content_type
      when 'application/json'
        response = new_nst.to_json
      when 'application/x-yaml'
        response = json_to_yaml(new_nst.to_json)
      else
        halt 415
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method update_nsts_id
  # @overload put '/catalogues/nsts/:id/?'
  #	Update a NST by its ID in JSON or YAML format
  ## Catalogue - UPDATE
  put '/nsts/:id/?' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?
      logger.debug "Catalogue: PUT /v2/nsts/#{params[:id]}"

      #Delete key "captures" if present
      params.delete(:captures) if params.key?(:captures)

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)

      # Check for special case (:status param == <new_status>)
      if keyed_params.key?(:status)
        # Do update of Descriptor status -> update_nst_status
        logger.info "Catalogue: entered PUT /v2/nsts/#{query_string}"

        # Validate NST
        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          nst = Nstd.find_by({ '_id' => params[:id] })
          puts 'NST is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This NST does not exists'
        end

        #Validate new status
        valid_status = %w(active inactive delete)
        if valid_status.include? keyed_params[:status]
          # Update to new status
          begin
            nst.update_attributes(status: keyed_params[:status])
          rescue Moped::Errors::OperationFailure => e
            json_error 400, 'ERROR: Operation failed'
          end
        else
          json_error 400, "Invalid new status #{keyed_params[:status]}"
        end
        halt 200, "Status updated to {#{query_string}}"

      else
        # Compatibility support for YAML content-type
        case request.content_type
          when 'application/x-yaml'
            # Validate YAML format
            # When updating a NST, the json object sent to API must contain just data inside
            # of the nstd, without the json field nstd: before
            nst, errors = parse_yaml(request.body.read)
            halt 400, errors.to_json if errors

            # Translate from YAML format to JSON format
            new_nst_json = yaml_to_json(nst)

            # Validate JSON format
            new_nst, errors = parse_json(new_nst_json)
            halt 400, errors.to_json if errors

          else
            # Compatibility support for JSON content-type
            # Parses and validates JSON format
            new_nst, errors = parse_json(request.body.read)
            halt 400, errors.to_json if errors
        end

        # Validate NST
        # Check if mandatory fields Vendor, Name, Version are included
        json_error 400, 'ERROR: NST Vendor not found' unless new_nst.has_key?('vendor')
        json_error 400, 'ERROR: NST Name not found' unless new_nst.has_key?('name')
        json_error 400, 'ERROR: NST Version not found' unless new_nst.has_key?('version')

        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          nst = Nstd.find_by({ '_id' => params[:id] })
          puts 'NST is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The NST ID #{params[:id]} does not exist"
        end

        # Check if NST already exists in the catalogue by name, vendor and version
        begin
          nst = Nstd.find_by({ 'nstd.name' => new_nst['name'], 'nstd.vendor' => new_nst['vendor'],
                               'nstd.version' => new_nst['version'] })
          json_return 200, 'Duplicated NST Name, Vendor and Version'
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
        new_nstd = {}
        new_nstd['_id'] = SecureRandom.uuid # Unique UUIDs per NST entries
        new_nstd['nstd'] = new_nst
        new_nstd['status'] = 'active'
        new_nstd['signature'] = nil
        new_nstd['md5'] = checksum new_nst.to_s
        new_nstd['username'] = username

        begin
          new_nst = Nstd.create!(new_nstd)
        rescue Moped::Errors::OperationFailure => e
          json_return 200, 'Duplicated NST ID' if e.message.include? 'E11000'
        end
        logger.debug "Catalogue: leaving PUT /v2/nsts/#{params[:id]}\" with NST #{new_nst}"

        response = ''
        case request.content_type
          when 'application/json'
            response = new_nst.to_json
          when 'application/x-yaml'
            response = json_to_yaml(new_nst.to_json)
          else
            halt 415
        end
        halt 200, {'Content-type' => request.content_type}, response
      end
    end
    logger.debug "Catalogue: leaving PUT /v2/nsts/#{params[:id]} with 'No NST ID specified'"
    json_error 400, 'No NST ID specified'
  end

  # @method delete_nstd_sp_nst
  # @overload delete '/nsts/?'
  #	Delete a NST by vendor, name and version
  delete '/nsts/?' do
    logger.info "Catalogue: entered DELETE /v2/nsts?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    unless keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      begin
        nst = Nstd.find_by({ 'nstd.vendor' => keyed_params[:vendor], 'nstd.name' => keyed_params[:name],
                            'nstd.version' => keyed_params[:version] })
        puts 'NST is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The NST Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
      logger.debug "Catalogue: leaving DELETE /v2/nsts?#{query_string}\" with NST #{nst}"
      nst.destroy
      halt 200, 'OK: NST removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/nsts?#{query_string} with 'No NST Vendor, Name, Version specified'"
    json_error 400, 'No NST Vendor, Name, Version specified'
  end

  # @method delete_nstd_sp_nst_id
  # @overload delete '/catalogues/nsts/:id/?'
  #	  Delete a NST by its ID
  #	  @param :id [Symbol] id NST ID
  # Delete a NST by uuid
  delete '/nsts/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: DELETE /v2/nsts/#{params[:id]}"
      begin
        nst = Nstd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The NST ID #{params[:id]} does not exist" unless nst
      end
      logger.debug "Catalogue: leaving DELETE /v2/nsts/#{params[:id]}\" with NST #{nst}"
      nst.destroy
      halt 200, 'OK: NST removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/nsts/#{params[:id]} with 'No NST ID specified'"
    json_error 400, 'No NST ID specified'
  end
end
