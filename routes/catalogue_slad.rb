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

class CatalogueV2 < SonataCatalogue
  ### SLAD API METHODS ###

  # @method get_slad
  # @overload get '/catalogues/sla/?'
  #	Returns a list of SLAs
  # -> List many descriptors
  get '/sla/?' do
    params['offset'] ||= DEFAULT_OFFSET
    params['limit'] ||= DEFAULT_LIMIT
    logger.info "Catalogue: entered GET /api/v2/sla?#{query_string}"

    # Split keys in meta_data and data
    # Then transform 'string' params Hash into keys
    keyed_params = add_descriptor_level('slad', params)

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
    if keyed_params.key?(:'slad.version') && keyed_params[:'slad.version'] == 'last'
      keyed_params.delete(:'slad.version')

      sla = Slad.where((keyed_params)).sort({ 'slad.version' => -1 }) #.limit(1).first()
      logger.info "Catalogue: SLADs=#{sla}"

      if sla && sla.size.to_i > 0
        logger.info "Catalogue: leaving GET /api/v2/sla?#{query_string} with #{sla}"

        sla_list = []
        checked_list = []

        sla_name_vendor = Pair.new(sla.first.slad['name'], sla.first.slad['vendor'])
        checked_list.push(sla_name_vendor)
        sla_list.push(sla.first)

        sla.each do |slad|
          if (slad.slad['name'] != sla_name_vendor.one) || (slad.slad['vendor'] != sla_name_vendor.two)
            sla_name_vendor = Pair.new(slad.slad['name'], slad.slad['vendor'])
          end
          sla_list.push(slad) unless checked_list.any? { |pair| pair.one == sla_name_vendor.one &&
              pair.two == sla_name_vendor.two }
          checked_list.push(sla_name_vendor)
        end
      else
        logger.info "Catalogue: leaving GET /api/v2/sla?#{query_string} with 'No SLADs were found'"
        sla_list = []

      end
      sla = apply_limit_and_offset(sla_list, offset=params[:offset], limit=params[:limit])

    else
      # Do the query
      sla = Slad.where(keyed_params)
      # Set total count for results
      headers 'Record-Count' => sla.count.to_s
      logger.info "Catalogue: SLADs=#{sla}"
      if sla && sla.size.to_i > 0
        logger.info "Catalogue: leaving GET /api/v2/sla?#{query_string} with #{sla}"
        # Paginate results
        sla = sla.paginate(offset: params[:offset], limit: params[:limit])
      else
        logger.info "Catalogue: leaving GET /api/v2/sla?#{query_string} with 'No SLADs were found'"
      end
    end

    response = ''
    case request.content_type
      when 'application/json'
        response = sla.to_json
      when 'application/x-yaml'
        response = json_to_yaml(sla.to_json)
      else
        halt 415
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method get_sla_id
  # @overload get '/catalogues/sla/:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] id SLA ID
  # Show a SLA by internal ID (uuid)
  get '/sla/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: GET /api/v2/sla/#{params[:id]}"

      begin
        sla = Slad.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The SLAD ID #{params[:id]} does not exist" unless sla
      end
      logger.debug "Catalogue: leaving GET /api/v2/sla/#{params[:id]}\" with SLAD #{sla}"

      response = ''
      case request.content_type
        when 'application/json'
          response = sla.to_json
        when 'application/x-yaml'
          response = json_to_yaml(sla.to_json)
        else
          halt 415
      end
      halt 200, {'Content-type' => request.content_type}, response

    end
    logger.debug "Catalogue: leaving GET /api/v2/sla/#{params[:id]} with 'No SLAD ID specified'"
    json_error 400, 'No SLAD ID specified'
  end

  # @method post_sla
  # @overload post '/catalogues/sla'
  # Post a SLA in JSON or YAML format
  post '/sla' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a SLAD, the json object sent to API must contain just data inside
        # of the slad, without the json field slad: before
        sla, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_sla_json = yaml_to_json(sla)

        # Validate JSON format
        new_sla, errors = parse_json(new_sla_json)
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_sla, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Validate sla
    json_error 400, 'ERROR: SLA Vendor not found' unless new_sla.has_key?('vendor')
    json_error 400, 'ERROR: SLA Name not found' unless new_sla.has_key?('name')
    json_error 400, 'ERROR: sla Version not found' unless new_sla.has_key?('version')

    # Check if SLAD already exists in the catalogue by name, vendor and version
    begin
      sla = Slad.find_by({ 'slad.name' => new_sla['name'], 'slad.vendor' => new_sla['vendor'],
                           'slad.version' => new_sla['version'] })
      json_return 200, 'Duplicated SLA Name, Vendor and Version'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end
    # Check if SLAD has an ID (it should not) and if it already exists in the catalogue
    begin
      sla = Slad.find_by({ '_id' => new_sla['_id'] })
      json_return 200, 'Duplicated SLA ID'
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
      new_slad = {}
      new_slad['slad'] = new_sla
      # Generate the UUID for the descriptor
      new_slad['_id'] = SecureRandom.uuid
      new_slad['signature'] = nil
      new_slad['md5'] = checksum new_sla.to_s
      new_slad['username'] = username
      sla = Slad.create!(new_slad)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated SLA ID' if e.message.include? 'E11000'
    end

    puts 'New SLA has been added'
    response = ''
    case request.content_type
      when 'application/json'
        response = sla.to_json
      when 'application/x-yaml'
        response = json_to_yaml(sla.to_json)
      else
        halt 415
    end
    halt 201, {'Content-type' => request.content_type}, response
  end

  # @method update_sla
  # @overload put '/sla/?'
  # Update a sla by vendor, name and version in JSON or YAML format
  ## Catalogue - UPDATE
  put '/sla/?' do
    logger.info "Catalogue: entered PUT /api/v2/sla?#{query_string}"

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
        # When updating a SLAD, the json object sent to API must contain just data inside
        # of the slad, without the json field slad: before
        sla, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_sla_json = yaml_to_json(sla)

        # Validate JSON format
        new_sla, errors = parse_json(new_sla_json)
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_sla, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    # Validate NS
    # Check if mandatory fields Vendor, Name, Version are included
    json_error 400, 'ERROR: SLA Vendor not found' unless new_sla.has_key?('vendor')
    json_error 400, 'ERROR: SLA Name not found' unless new_sla.has_key?('name')
    json_error 400, 'ERROR: SLA Version not found' unless new_sla.has_key?('version')

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
        sla = Slad.find_by({ 'slad.vendor' => keyed_params[:vendor], 'slad.name' => keyed_params[:name],
                            'slad.version' => keyed_params[:version] })
        puts 'SLA is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The SLAD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
    end
    # Check if SLA already exists in the catalogue by Name, Vendor and Version
    begin
      sla = Slad.find_by({ 'slad.name' => new_sla['name'], 'slad.vendor' => new_sla['vendor'],
                           'slad.version' => new_sla['version'] })
      json_return 200, 'Duplicated SLA Name, Vendor and Version'
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
    new_slad = {}
    new_slad['_id'] = SecureRandom.uuid # Unique UUIDs per SLAD entries
    new_slad['slad'] = new_sla
    new_slad['signature'] = nil
    new_slad['md5'] = checksum new_sla.to_s
    new_slad['username'] = username

    begin
      new_sla = Slad.create!(new_slad)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated SLA ID' if e.message.include? 'E11000'
    end
    logger.debug "Catalogue: leaving PUT /api/v2/sla?#{query_string}\" with SLAD #{new_sla}"

    response = ''
    case request.content_type
      when 'application/json'
        response = new_sla.to_json
      when 'application/x-yaml'
        response = json_to_yaml(new_sla.to_json)
      else
        halt 415
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method update_sla_id
  # @overload put '/catalogues/sla/:id/?'
  #	Update a SLA by its ID in JSON or YAML format
  ## Catalogue - UPDATE
  put '/sla/:id/?' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?
      logger.debug "Catalogue: PUT /api/v2/sla/#{params[:id]}"

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)

      # Compatibility support for YAML content-type
      case request.content_type
        when 'application/x-yaml'
          # Validate YAML format
          # When updating a SLAD, the json object sent to API must contain just data inside
          # of the slad, without the json field slad: before
          sla, errors = parse_yaml(request.body.read)
          halt 400, errors.to_json if errors

          # Translate from YAML format to JSON format
          new_sla_json = yaml_to_json(sla)

          # Validate JSON format
          new_sla, errors = parse_json(new_sla_json)
          halt 400, errors.to_json if errors

        else
          # Compatibility support for JSON content-type
          # Parses and validates JSON format
          new_sla, errors = parse_json(request.body.read)
          halt 400, errors.to_json if errors
      end

      # Validate SLA
      # Check if mandatory fields Vendor, Name, Version are included
      json_error 400, 'ERROR: SLA Vendor not found' unless new_sla.has_key?('vendor')
      json_error 400, 'ERROR: SLA Name not found' unless new_sla.has_key?('name')
      json_error 400, 'ERROR: SLA Version not found' unless new_sla.has_key?('version')

      # Retrieve stored version
      begin
        puts 'Searching ' + params[:id].to_s
        sla = Slad.find_by({ '_id' => params[:id] })
        puts 'SLA is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The SLAD ID #{params[:id]} does not exist"
      end

      # Check if sla already exists in the catalogue by name, vendor and version
      begin
        sla = Slad.find_by({ 'slad.name' => new_sla['name'], 'slad.vendor' => new_sla['vendor'],
                             'slad.version' => new_sla['version'] })
        json_return 200, 'Duplicated SLA Name, Vendor and Version'
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
      new_slad = {}
      new_slad['_id'] = SecureRandom.uuid # Unique UUIDs per SLAD entries
      new_slad['slad'] = new_sla
      new_slad['signature'] = nil
      new_slad['md5'] = checksum new_sla.to_s
      new_slad['username'] = username

      begin
        new_sla = Slad.create!(new_slad)
      rescue Moped::Errors::OperationFailure => e
        json_return 200, 'Duplicated SLA ID' if e.message.include? 'E11000'
      end
      logger.debug "Catalogue: leaving PUT /api/v2/sla/#{params[:id]}\" with SLAD #{new_sla}"

      response = ''
      case request.content_type
        when 'application/json'
          response = new_sla.to_json
        when 'application/x-yaml'
          response = json_to_yaml(new_sla.to_json)
        else
          halt 415
      end
      halt 200, {'Content-type' => request.content_type}, response
    end
    logger.debug "Catalogue: leaving PUT /api/v2/sla/#{params[:id]} with 'No SLA ID specified'"
    json_error 400, 'No SLA ID specified'
  end

  # @method delete_slad_sp_sla
  # @overload delete '/sla/?'
  #	Delete a SLA by vendor, name and version
  delete '/sla/?' do
    logger.info "Catalogue: entered DELETE /api/v2/sla?#{query_string}"

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    unless keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      begin
        sla = Slad.find_by({ 'slad.vendor' => keyed_params[:vendor], 'slad.name' => keyed_params[:name],
                            'slad.version' => keyed_params[:version] })
        puts 'SLA is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The SLAD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
      logger.debug "Catalogue: leaving DELETE /api/v2/sla?#{query_string}\" with SLAD #{sla}"
      sla.destroy
      halt 200, 'OK: SLAD removed'
    end
    logger.debug "Catalogue: leaving DELETE /api/v2/sla?#{query_string} with 'No SLAD Vendor, Name, Version specified'"
    json_error 400, 'No SLAD Vendor, Name, Version specified'
  end

  # @method delete_slad_sp_sla_id
  # @overload delete '/catalogues/sla/:id/?'
  #	  Delete a SLA by its ID
  #	  @param :id [Symbol] id SLA ID
  # Delete a SLA by uuid
  delete '/sla/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: DELETE /api/v2/sla/#{params[:id]}"
      begin
        sla = Slad.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The SLAD ID #{params[:id]} does not exist" unless sla
      end
      logger.debug "Catalogue: leaving DELETE /api/v2/sla/#{params[:id]}\" with SLAD #{sla}"
      sla.destroy
      halt 200, 'OK: SLAD removed'
    end
    logger.debug "Catalogue: leaving DELETE /api/v2/sla/#{params[:id]} with 'No SLAD ID specified'"
    json_error 400, 'No SLAD ID specified'
  end
end
