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
  ### SLAD API METHODS ###

  # @method get_slas
  # @overload get '/catalogues/sla/template-descriptors?'
  #	Returns a list of SLA template descriptors
  # -> List many descriptors
  get '/slas/template-descriptors/?' do
    params['offset'] ||= DEFAULT_OFFSET
    params['limit'] ||= DEFAULT_LIMIT
    logger.info "Catalogue: entered GET /v2/slas/template-descriptors?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

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
      # Do query for last version -> get_slad_sla_vendor_last_version
      keyed_params.delete(:'slad.version')

      slas = Slad.where((keyed_params)).sort({ 'slad.version' => -1 })
      logger.info "Catalogue: SLADs=#{slas}"

      if slas && slas.size.to_i > 0
        logger.info "Catalogue: leaving GET /v2/slas/template-descriptors?#{query_string} with #{slas}"

        slas_list = []
        checked_list = []
        slas_name_vendor = Pair.new(slas.first.slad['name'], slas.first.slad['vendor'])
        checked_list.push(slas_name_vendor)
        slas_list.push(slas.first)

        slas.each do |slad|
          if (slad.slas['name'] != slas_name_vendor.one) || (slad.slad['vendor'] != slas_name_vendor.two)
            slas_name_vendor = Pair.new(slad.slad['name'], slad.slad['vendor'])
          end
          slas_list.push(slad) unless checked_list.any? { |pair| pair.one == slas_name_vendor.one &&
              pair.two == slas_name_vendor.two }
          checked_list.push(slas_name_vendor)
        end
      else
        logger.info "Catalogue: leaving GET /v2/slas/template-descriptors?#{query_string} with 'No SLADs were found'"
        slas_list = []

      end
      slas = apply_limit_and_offset(slas_list, offset=params[:offset], limit=params[:limit])

    else
      # Do the query
      keyed_params = parse_keys_dict(:slad, keyed_params)
      slas = Slad.where(keyed_params)
      # Set total count for results
      headers 'Record-Count' => slas.count.to_s
      logger.info "Catalogue: SLADs=#{slas}"
      if slas && slas.size.to_i > 0
        logger.info "Catalogue: leaving GET /v2/slas/template-descriptors?#{query_string} with #{slas}"
        # Paginate results
        slas = slas.paginate(offset: params[:offset], limit: params[:limit])
      else
        logger.info "Catalogue: leaving GET /v2/slas/template-descriptors?#{query_string} with 'No SLADs were found'"
      end
    end

    response = ''
    case request.content_type
      when 'application/json'
        response = slas.to_json
      when 'application/x-yaml'
        response = json_to_yaml(slas.to_json)
      else
        halt 415
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method get_slas_id
  # @overload get '/catalogues/sla/template-descriptor/:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] id SLA ID
  # Show a SLAd by internal ID (uuid)
  get '/slas/template-descriptors/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: GET /v2/slas/template-descriptors/#{params[:id]}"

      begin
        sla = Slad.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The SLAD ID #{params[:id]} does not exist" unless sla
      end
      logger.debug "Catalogue: leaving GET /v2/slas/template-descriptors/#{params[:id]}\" with SLAD #{sla}"

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
    logger.debug "Catalogue: leaving GET /v2/slas/template-descriptors/#{params[:id]} with 'No SLAD ID specified'"
    json_error 400, 'No SLAD ID specified'
  end

  # @method post_slas
  # @overload post '/catalogues/sla/template-descriptors/'
  # Post an SLAd in JSON or YAML format
  post '/slas/template-descriptors' do
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

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Validate SLA
    json_error 400, 'ERROR: SLA Vendor not found' unless new_sla.has_key?('vendor')
    json_error 400, 'ERROR: SLA Name not found' unless new_sla.has_key?('name')
    json_error 400, 'ERROR: SLA Version not found' unless new_sla.has_key?('version')

    # Check if SLAD already exists in the catalogue by name, vendor and version
    begin
      sla = Slad.find_by({ 'slad.name' => new_sla['name'], 'slad.vendor' => new_sla['vendor'],
                           'slad.version' => new_sla['version'] })
      halt 409, "Duplicate with SLA Template ID => #{sla['_id']}"
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end
    # Check if SLAD has an ID (it should not) and if it already exists in the catalogue
    begin
      sla = Slad.find_by({ '_id' => new_sla['_id'] })
      halt 409, 'Duplicated SLA ID'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    if keyed_params.key?(:username)
      username = keyed_params[:username]
    else
      username = nil
    end

    # Save to DB

    new_slad = {}
    new_slad['slad'] = new_sla
    # Generate the UUID for the descriptor
    new_slad['_id'] = SecureRandom.uuid
    new_slad['status'] = 'active'
    new_slad['published'] = false
    new_slad['signature'] = nil
    new_slad['md5'] = checksum new_sla.to_s
    new_slad['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_slad, :slad)

    begin
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

  # @method update_sla_template_descriptors
  # @overload put '/sla/template-descriptor/?'
  # Update a SLA by vendor, name and version in JSON or YAML format
  ## Catalogue - UPDATE
  put '/slas/template-descriptors/?' do
    logger.info "Catalogue: entered PUT /v2/slas/template-descriptors/#{query_string}"

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
    new_slad['status'] = 'active'
    new_slad['published'] = false
    new_slad['signature'] = nil
    new_slad['md5'] = checksum new_sla.to_s
    new_slad['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_slad, :slad)

    begin
      new_sla = Slad.create!(new_slad)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated SLA ID' if e.message.include? 'E11000'
    end
    logger.debug "Catalogue: leaving PUT /v2/sla/template-descriptors?#{query_string}\" with SLAD #{new_sla}"

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

  # @method update_sla_template_descriptors_id
  # @overload put '/catalogues/sla/template_descriptors/:id/?'
  #	Update a SLA by its ID in JSON or YAML format
  ## Catalogue - UPDATE
  put '/slas/template-descriptors/:id/?' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?
      logger.debug "Catalogue: PUT /v2/slas/template-descriptors/#{params[:id]}"

      #Delete key "captures" if present
      params.delete(:captures) if params.key?(:captures)

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)

      if keyed_params.key?(:status) || keyed_params.key?(:published)
        # Do update of Descriptor status -> update_sla_status
        logger.info "Catalogue: entered PUT /v2/slas/template-descriptors/#{query_string}"
        valid_published = %w[true false]
        valid_status = %w[active inactive]
        out_query1 = ''
        out_query2 = ''

        # Validate SLA
        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          sla = Slad.find_by('_id' => params[:id])
          puts 'SLA is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This SLAD does not exists'
        end
        # Validate state
        if keyed_params.key?(:published)
          if valid_published.include? keyed_params[:published]
            begin
              sla.update_attributes(published: keyed_params[:published] == 'true')
              out_query1 = 'published => ' + keyed_params[:published].to_s
            rescue Moped::Errors::OperationFailure => e
              json_error 400, 'ERROR: Operation failed'
            end
          else
            json_error 400, "Invalid new published state #{keyed_params[:published]}"
          end
        end

        # Validate new status
        if keyed_params.key?(:status)
          if valid_status.include? keyed_params[:status]
            # Update to new status
            begin
              sla.update_attributes(status: keyed_params[:status])
              out_query2 = 'status => ' + keyed_params[:status].to_s
            rescue Moped::Errors::OperationFailure => e
              json_error 400, 'ERROR: Operation failed'
            end

          else
            json_error 400, "Invalid new status #{keyed_params[:status]}"
          end
        end

        if out_query2.empty? ^ out_query1.empty?
          if out_query1.empty?
            halt 200, "Updated to {#{out_query2}}"
          else
            halt 200, "Updated to {#{out_query1}}"
          end
        else
          halt 200, "Updated to {#{out_query1}} and {#{out_query2}}"
        end
      else
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

        # Check if SLA already exists in the catalogue by name, vendor and version
        begin
          sla = Slad.find_by({ 'slad.name' => new_sla['name'], 'slad.vendor' => new_sla['vendor'],
                               'slad.version' => new_sla['version'] })
          json_return 200, 'Duplicated SLA Name, Vendor and Version'
        rescue Mongoid::Errors::DocumentNotFound => e
          # Continue
        end

        # # Check if SLAD is state == published. Then, it cannot be edited
        # json_error 400, "The SLAD is published and cannot be edited" if sla['state'] == 'published'


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
        new_slad['status'] = 'active'
        new_slad['published'] = false
        new_slad['signature'] = nil
        new_slad['md5'] = checksum new_sla.to_s
        new_slad['username'] = username

        # First, Refresh dictionary about the new entry
        update_entr_dict(new_slad, :slad)

        begin
          new_sla = Slad.create!(new_slad)
        rescue Moped::Errors::OperationFailure => e
          json_return 200, 'Duplicated SLA ID' if e.message.include? 'E11000'
        end
        logger.debug "Catalogue: leaving PUT /v2/slas/template-descriptors/#{params[:id]}\" with SLAD #{new_sla}"

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
    end
    logger.debug "Catalogue: leaving PUT /v2/slas/template-descriptors/#{params[:id]} with 'No SLA ID specified'"
    json_error 400, 'No SLA ID specified'
  end

  # @method delete_slad_sp_sla
  # @overload delete '/sla/template-descriptor/?'
  #	Delete a SLA by vendor, name and version
  delete '/slas/template-descriptors/?' do
    logger.info "Catalogue: entered DELETE /v2/slas/template-descriptors?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

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
      # Check if SLAD is unpublished and inactive. Then, it cannot be deleted
      logger.debug "Catalogue: leaving DELETE /v2/sla/template-descriptors?#{query_string}\" with SLAD #{sla}"
      # Delete entry in dict mapping
      del_ent_dict(sla, :slad)
      sla.destroy
      halt 200, 'OK: SLAD removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/slas/template-descriptors?#{query_string} with 'No SLAD Vendor, Name, Version specified'"
    json_error 400, 'No SLAD Vendor, Name, Version specified'
  end

  # @method delete_slad_sp_sla_id
  # @overload delete '/catalogues/sla/template-descriptors/:id/?'
  #	  Delete a SLA by its ID
  #	  @param :id [Symbol] id SLA ID
  # Delete a SLA by uuid
  delete '/slas/template-descriptors/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: DELETE /v2/slas/template-descriptors/#{params[:id]}"
      begin
        sla = Slad.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The SLAD ID #{params[:id]} does not exist" unless sla
      end
      logger.debug "Catalogue: leaving DELETE /v2/slas/template-descriptors?#{query_string}\" with SLAD #{sla}"
      # Delete entry in dict mapping
      del_ent_dict(sla, :slad)
      sla.destroy
      halt 200, 'OK: SLAD removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/slas/template-descriptors/#{params[:id]} with 'No SLAD ID specified'"
    json_error 400, 'No SLAD ID specified'
  end
end
