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
  ### PLD API METHODS ###

  # @method get_policies
  # @overload get '/catalogues/policies/?'
  #	Returns a list of policies
  # -> List many descriptors
  get '/policies/?' do
    params['offset'] ||= DEFAULT_OFFSET
    params['limit'] ||= DEFAULT_LIMIT
    logger.info "Catalogue: entered GET v2/policies?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Split keys in meta_data and data
    # Then transform 'string' params Hash into keys
    keyed_params = add_descriptor_level('pld', params)

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
    # if keyed_params.key?(:'pld.version') && keyed_params[:'pld.version'] == 'last'
    #   # Do query for last version -> get_pld_pl_vendor_last_version
    #   keyed_params.delete(:'pld.version')
    #
    #   policies = Pld.where((keyed_params)).sort({ 'pld.version' => -1 }) #.limit(1).first()
    #   logger.info "Catalogue: PLDs=#{policies}"
    #
    #   if policies && policies.size.to_i > 0
    #     logger.info "Catalogue: leaving GET /api/v2/policies?#{query_string} with #{policies}"
    #
    #     policies_list = []
    #     checked_list = []
    #
    #     policies_name_vendor = Pair.new(policies.first.pold['name'], policies.first.pold['vendor'])
    #     checked_list.push(policies_name_vendor)
    #     policies_list.push(policies.first)
    #
    #     policies.each do |pold|
    #       if (pold.pold['name'] != policies_name_vendor.one) || (pold.pold['vendor'] != policies_name_vendor.two)
    #         policies_name_vendor = Pair.new(pold.pold['name'], pold.pold['vendor'])
    #       end
    #       policies_list.push(pold) unless checked_list.any? { |pair| pair.one == policies_name_vendor.one &&
    #           pair.two == policies_name_vendor.two }
    #       checked_list.push(policies_name_vendor)
    #     end
    #   else
    #     logger.info "Catalogue: leaving GET /api/v2/policies?#{query_string} with 'No PLDs were found'"
    #     policies_list = []
    #
    #   end
    #   policies = apply_limit_and_offset(policies_list, offset=params[:offset], limit=params[:limit])
    #
    # else

    # Do the query
    keyed_params = parse_keys_dict(:pld, keyed_params)
    policies = Pld.where(keyed_params)
    # Set total count for results
    headers 'Record-Count' => policies.count.to_s
    logger.info "Catalogue: PLDs=#{policies}"
    if policies && policies.size.to_i > 0
      logger.info "Catalogue: leaving GET v2/policies?#{query_string} with #{policies}"
      # Paginate results
      policies = policies.paginate(offset: params[:offset], limit: params[:limit])
    else
      logger.info "Catalogue: leaving GET v2/policies?#{query_string} with 'No PLDs were found'"
    end

    response = ''
    case request.content_type
      when 'application/json'
        response = policies.to_json
      when 'application/x-yaml'
        response = json_to_yaml(policies.to_json)
      else
        halt 415
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method get_policies_id
  # @overload get '/catalogues/policies/:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] id Policy ID
  # Show a Policy by internal ID (uuid)
  get '/policies/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: GET v2/policies/#{params[:id]}"

      begin
        pl = Pld.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The PLD ID #{params[:id]} does not exist" unless pl
      end
      logger.debug "Catalogue: leaving GET v2/policies/#{params[:id]}\" with PLD #{pl}"

      response = ''
      case request.content_type
        when 'application/json'
          response = pl.to_json
        when 'application/x-yaml'
          response = json_to_yaml(pl.to_json)
        else
          halt 415
      end
      halt 200, {'Content-type' => request.content_type}, response

    end
    logger.debug "Catalogue: leaving GET v2/policies/#{params[:id]} with 'No PLD ID specified'"
    json_error 400, 'No PLD ID specified'
  end

  # @method post_policies
  # @overload post '/catalogues/policies'
  # Post a Policy in JSON or YAML format
  post '/policies' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a PLD, the json object sent to API must contain just data inside
        # of the pld, without the json field pld: before
        pl, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_pl_json = yaml_to_json(pl)

        # Validate JSON format
        new_pl, errors = parse_json(new_pl_json)
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_pl, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Validate Policy
    json_error 400, 'ERROR: Policy Name not found' unless new_pl.has_key?('name')
    # Check if PLD already exists in the catalogue by name
    begin
      pl = Pld.find_by({ 'pld.name' => new_pl['name'] })
      halt 409, "Duplicate with PD ID => #{pl['_id']}"
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end
    # Check if PLD has an ID (it should not) and if it already exists in the catalogue
    begin
      pl = Pld.find_by({ '_id' => new_pl['_id'] })
      halt 409, 'Duplicated Policy ID'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    if keyed_params.key?(:username)
      username = keyed_params[:username]
    else
      username = nil
    end

    # Save to DB
    new_pld = {}
    new_pld['pld'] = new_pl
    # Generate the UUID for the descriptor
    new_pld['_id'] = SecureRandom.uuid
    new_pld['status'] = 'active'
    new_pld['signature'] = nil
    new_pld['md5'] = checksum new_pl.to_s
    new_pld['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_pld, :pld)

    begin
      pl = Pld.create!(new_pld)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated Policy ID' if e.message.include? 'E11000'
    end

    puts 'New Policy has been added'
    response = ''
    case request.content_type
      when 'application/json'
        response = pl.to_json
      when 'application/x-yaml'
        response = json_to_yaml(pl.to_json)
      else
        halt 415
    end
    halt 201, {'Content-type' => request.content_type}, response
  end

  # @method update_policies
  # @overload put '/policies/?'
  # Update a Policy by name in JSON or YAML format
  ## Catalogue - UPDATE
  put '/policies/?' do
    logger.info "Catalogue: entered PUT v2/policies?#{query_string}"

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
        # When updating a PLD, the json object sent to API must contain just data inside
        # of the pld, without the json field pld: before
        pl, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_pl_json = yaml_to_json(pl)

        # Validate JSON format
        new_pl, errors = parse_json(new_pl_json)
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_pl, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    # Validate Policy
    # Check if mandatory field Name is included
    json_error 400, 'ERROR: Policy Name not found' unless new_pl.has_key?('name')

    # Set headers
    case request.content_type
      when 'application/x-yaml'
        headers = { 'Accept' => 'application/x-yaml', 'Content-Type' => 'application/x-yaml' }
      else
        headers = { 'Accept' => 'application/json', 'Content-Type' => 'application/json' }
    end
    headers[:params] = params unless params.empty?

    # Retrieve stored version
    if keyed_params[:name].nil?
      json_error 400, 'Update Name parameter are null'
    else
      begin
        pl = Pld.find_by('pld.name' => keyed_params[:name])
        puts 'Policy is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The Name #{keyed_params[:name]} does not exist"
      end
    end
    # Check if Policy already exists in the catalogue by Name
    begin
      pl = Pld.find_by('pld.name' => new_pl['name'])
      json_return 200, 'Duplicated Policy Name'
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
    new_pld = {}
    new_pld['_id'] = SecureRandom.uuid # Unique UUIDs per PLD entries
    new_pld['pld'] = new_pl
    new_pld['status'] = 'active'
    new_pld['signature'] = nil
    new_pld['md5'] = checksum new_pl.to_s
    new_pld['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_pld, :pld)

    begin
      new_pl = Pld.create!(new_pld)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated Policy ID' if e.message.include? 'E11000'
    end
    logger.debug "Catalogue: leaving PUT v2/policies?#{query_string}\" with PLD #{new_pl}"

    response = ''
    case request.content_type
      when 'application/json'
        response = new_pl.to_json
      when 'application/x-yaml'
        response = json_to_yaml(new_pl.to_json)
      else
        halt 415
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method update_policies_id
  # @overload put '/catalogues/policies/:id/?'
  #	Update a Policy by its ID in JSON or YAML format
  ## Catalogue - UPDATE
  put '/policies/:id/?' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?
      logger.debug "Catalogue: PUT v2/policies/#{params[:id]}"

      #Delete key "captures" if present
      params.delete(:captures) if params.key?(:captures)

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)

      # Check for special case (:status param == <new_status>)
      if keyed_params.key?(:status)
        # Do update of Descriptor status -> update_policy_status
        logger.info "Catalogue: entered PUT v2/policies/#{query_string}"

        # Validate Policy
        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          pl = Pld.find_by({ '_id' => params[:id] })
          puts 'Policy is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This PLD does not exists'
        end

        #Validate new status
        valid_status = %w(active inactive delete)
        if valid_status.include? keyed_params[:status]
          # Update to new status
          begin
            pl.update_attributes(status: keyed_params[:status])
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
            # When updating a PLD, the json object sent to API must contain just data inside
            # of the pld, without the json field pld: before
            pl, errors = parse_yaml(request.body.read)
            halt 400, errors.to_json if errors

            # Translate from YAML format to JSON format
            new_pl_json = yaml_to_json(pl)

            # Validate JSON format
            new_pl, errors = parse_json(new_pl_json)
            halt 400, errors.to_json if errors

          else
            # Compatibility support for JSON content-type
            # Parses and validates JSON format
            new_pl, errors = parse_json(request.body.read)
            halt 400, errors.to_json if errors
        end

        # Validate Policy Descriptor
        # Check if mandatory field Name is included
        json_error 400, 'ERROR: Policy Name not found' unless new_pl.has_key?('name')

        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          pl = Pld.find_by({ '_id' => params[:id] })
          puts 'Policy is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The PLD ID #{params[:id]} does not exist"
        end

        # Check if PLD already exists in the catalogue by name
        begin
          pl = Pld.find_by( 'pld.name' => new_pl['name'])
          json_return 200, 'Duplicated Policy Name'
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
        new_pld = {}
        new_pld['_id'] = SecureRandom.uuid # Unique UUIDs per Policy entries
        new_pld['pld'] = new_pl
        new_pld['status'] = 'active'
        new_pld['signature'] = nil
        new_pld['md5'] = checksum new_pl.to_s
        new_pld['username'] = username

        # First, Refresh dictionary about the new entry
        update_entr_dict(new_pld, :pld)

        begin
          new_pl = Pld.create!(new_pld)
        rescue Moped::Errors::OperationFailure => e
          json_return 200, 'Duplicated Policy ID' if e.message.include? 'E11000'
        end
        logger.debug "Catalogue: leaving PUT v2/policies/#{params[:id]}\" with PLD #{new_pl}"

        response = ''
        case request.content_type
          when 'application/json'
            response = new_pl.to_json
          when 'application/x-yaml'
            response = json_to_yaml(new_pl.to_json)
          else
            halt 415
        end
        halt 200, {'Content-type' => request.content_type}, response
      end
    end
    logger.debug "Catalogue: leaving PUT v2/policies/#{params[:id]} with 'No Policy ID specified'"
    json_error 400, 'No Policy ID specified'
  end

  # @method delete_pld_sp_policy
  # @overload delete '/policies/?'
  #	Delete a policy by name
  delete '/policies/?' do
    logger.info "Catalogue: entered DELETE /v2/policies?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    unless keyed_params[:name].nil?
      begin
        pl = Pld.find_by('pld.name' => keyed_params[:name])
        puts 'Policy is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The PLD Name #{keyed_params[:name]} does not exist"
      end
      logger.debug "Catalogue: leaving DELETE /v2/policies?#{query_string}\" with PLD #{pl}"
      # Delete entry in dict mapping
      del_ent_dict(pl, :pld)
      pl.destroy
      halt 200, 'OK: PLD removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/policies?#{query_string} with 'No PLD Name specified'"
    json_error 400, 'No PLD Name specified'
  end

  # @method delete_pld_sp_pl_id
  # @overload delete '/catalogues/policies/:id/?'
  #	  Delete a policy by its ID
  #	  @param :id [Symbol] id Policy ID
  # Delete a Policy by uuid
  delete '/policies/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: DELETE /v2/policies/#{params[:id]}"
      begin
        pl = Pld.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The PLD ID #{params[:id]} does not exist" unless pl
      end
      logger.debug "Catalogue: leaving DELETE /v2/policies/#{params[:id]}\" with PLD #{pl}"
      # Delete entry in dict mapping
      del_ent_dict(pl, :pld)
      pl.destroy
      halt 200, 'OK: PLD removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/policies/#{params[:id]} with 'No PLD ID specified'"
    json_error 400, 'No PLD ID specified'
  end
end
