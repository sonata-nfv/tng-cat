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
  ### TESTD API METHODS ###

  # @method get_test_descriptors
  # @overload get '/catalogues/tests/?'
  #	Returns a list of Test Descriptors
  # -> List many descriptors
  get '/tests/?' do
    params['page_number'] ||= DEFAULT_PAGE_NUMBER
    params['page_size'] ||= DEFAULT_PAGE_SIZE
    logger.info "Catalogue: entered GET /v2/tests?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Split keys in meta_data and data
    # Then transform 'string' params Hash into keys
    keyed_params = add_descriptor_level('testd', params)

    # Set headers
    case request.content_type
      when 'application/x-yaml'
        headers = { 'Accept' => 'application/x-yaml', 'Content-Type' => 'application/x-yaml' }
      else
        headers = { 'Accept' => 'application/json', 'Content-Type' => 'application/json' }
    end
    headers[:params] = params unless params.empty?

    # Get rid of :page_number and :page_number
    [:page_number, :page_size].each { |k| keyed_params.delete(k) }

    # Check for special case (:version param == last)
    if keyed_params.key?(:'testd.version') && keyed_params[:'testd.version'] == 'last'
      # Do query for last version -> get_testd_test_vendor_last_version
      keyed_params.delete(:'testd.version')

      tests = Testd.where((keyed_params)).sort({ 'testd.version' => -1 }) #.limit(1).first()
      logger.info "Catalogue: TESTDs=#{tests}"

      if tests && tests.size.to_i > 0
        logger.info "Catalogue: leaving GET /v2/tests?#{query_string} with #{tests}"

        tests_list = []
        checked_list = []

        tests_name_vendor = Pair.new(tests.first.testd['name'], tests.first.testd['vendor'])
        checked_list.push(tests_name_vendor)
        tests_list.push(tests.first)

        tests.each do |testd|
          if (testd.testd['name'] != tests_name_vendor.one) || (testd.testd['vendor'] != tests_name_vendor.two)
            tests_name_vendor = Pair.new(testd.testd['name'], testd.testd['vendor'])
          end
          tests_list.push(testd) unless checked_list.any? { |pair| pair.one == tests_name_vendor.one &&
              pair.two == tests_name_vendor.two }
          checked_list.push(tests_name_vendor)
        end
      else
        logger.info "Catalogue: leaving GET /v2/tests?#{query_string} with 'No TESTDs were found'"
        tests_list = []

      end
      tests = apply_limit_and_offset(tests_list, page_number=params[:page_number], page_size=params[:page_size])

    else
      # Do the query
      keyed_params = parse_keys_dict(:testd, keyed_params)
      tests = Testd.where(keyed_params)
      # Set total count for results
      headers 'Record-Count' => tests.count.to_s
      logger.info "Catalogue: TESTDs=#{tests}"
      if tests && tests.size.to_i > 0
        logger.info "Catalogue: leaving GET /v2/tests?#{query_string} with #{tests}"
        # Paginate results
        tests = tests.paginate(page_number: params[:page_number], page_size: params[:page_size])
      else
        logger.info "Catalogue: leaving GET /v2/tests?#{query_string} with 'No TESTDs were found'"
      end
    end

    response = ''
    case request.content_type
      when 'application/json'
        response = tests.to_json
      when 'application/x-yaml'
        response = json_to_yaml(tests.to_json)
      else
        halt 415
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method get_tests_id
  # @overload get '/catalogues/tests/:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] id TEST ID
  # Show a Test Descriptor by internal ID (uuid)
  get '/tests/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: GET /v2/tests/#{params[:id]}"

      begin
        test = Testd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The TESTD ID #{params[:id]} does not exist" unless test
      end
      logger.debug "Catalogue: leaving GET /v2/tests/#{params[:id]}\" with TESTD #{test}"

      response = ''
      case request.content_type
        when 'application/json'
          response = test.to_json
        when 'application/x-yaml'
          response = json_to_yaml(test.to_json)
        else
          halt 415
      end
      halt 200, {'Content-type' => request.content_type}, response

    end
    logger.debug "Catalogue: leaving GET /v2/tests/#{params[:id]} with 'No TESTD ID specified'"
    json_error 400, 'No TESTD ID specified'
  end

  # @method post_tests
  # @overload post '/catalogues/tests'
  # Post a Test Descriptor in JSON or YAML format
  post '/tests' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a Test Descriptor, the json object sent to API must contain just data inside
        # of the test descriptor, without the json field testd: before
        test, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_test_json = yaml_to_json(test)

        # Validate JSON format
        new_test, errors = parse_json(new_test_json)
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_test, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Validate Test Descriptor
    json_error 400, 'ERROR: TEST Vendor not found' unless new_test.has_key?('vendor')
    json_error 400, 'ERROR: TEST Name not found' unless new_test.has_key?('name')
    json_error 400, 'ERROR: TEST Version not found' unless new_test.has_key?('version')

    # Check if Test Descriptor already exists in the catalogue by name, vendor and version
    begin
      test = Testd.find_by({ 'testd.name' => new_test['name'], 'testd.vendor' => new_test['vendor'],
                           'testd.version' => new_test['version'] })
      halt 409, "Duplicated TEST with ID => #{test['_id']}"
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end
    # Check if Test Descriptor has an ID (it should not) and if it already exists in the catalogue
    begin
      test = Testd.find_by({ '_id' => new_test['_id'] })
      halt 409, 'Duplicated TEST ID'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    if keyed_params.key?(:username)
      username = keyed_params[:username]
    else
      username = nil
    end

    # Save to DB
    new_testd = {}
    new_testd['testd'] = new_test
    # Generate the UUID for the descriptor
    new_testd['_id'] = SecureRandom.uuid
    new_testd['status'] = 'active'
    new_testd['signature'] = nil
    new_testd['md5'] = checksum new_test.to_s
    new_testd['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_testd, :testd)

    begin
      test = Testd.create!(new_testd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated TEST ID' if e.message.include? 'E11000'
    end

    puts 'New TEST Descriptor has been added'
    response = ''
    case request.content_type
      when 'application/json'
        response = test.to_json
      when 'application/x-yaml'
        response = json_to_yaml(test.to_json)
      else
        halt 415
    end
    halt 201, {'Content-type' => request.content_type}, response
  end

  # @method update_test_descriptors
  # @overload put '/tests/?'
  # Update a Test Descriptor by vendor, name and version in JSON or YAML format
  ## Catalogue - UPDATE
  put '/tests/?' do
    logger.info "Catalogue: entered PUT /v2/tests?#{query_string}"

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
        # When updating a Test Descriptor, the json object sent to API must contain just data inside
        # of the test descriptor, without the json field testd: before
        test, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_test_json = yaml_to_json(test)

        # Validate JSON format
        new_test, errors = parse_json(new_test_json)
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_test, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    # Validate NS
    # Check if mandatory fields Vendor, Name, Version are included
    json_error 400, 'ERROR: TEST Vendor not found' unless new_test.has_key?('vendor')
    json_error 400, 'ERROR: TEST Name not found' unless new_test.has_key?('name')
    json_error 400, 'ERROR: TEST Version not found' unless new_test.has_key?('version')

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
        test = Testd.find_by({ 'testd.vendor' => keyed_params[:vendor], 'testd.name' => keyed_params[:name],
                            'testd.version' => keyed_params[:version] })
        puts 'TEST Descriptor is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The TESTD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
    end
    # Check if Test Descriptor already exists in the catalogue by Name, Vendor and Version
    begin
      test = Testd.find_by({ 'testd.name' => new_test['name'], 'testd.vendor' => new_test['vendor'],
                           'testd.version' => new_test['version'] })
      json_return 200, 'Duplicated TEST Name, Vendor and Version'
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
    new_testd = {}
    new_testd['_id'] = SecureRandom.uuid # Unique UUIDs per Test Descriptor entries
    new_testd['testd'] = new_test
    new_testd['status'] = 'active'
    new_testd['signature'] = nil
    new_testd['md5'] = checksum new_test.to_s
    new_testd['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_testd, :testd)

    begin
      new_test = Testd.create!(new_testd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated TEST ID' if e.message.include? 'E11000'
    end
    logger.debug "Catalogue: leaving PUT /v2/tests?#{query_string}\" with TESTD #{new_test}"

    response = ''
    case request.content_type
      when 'application/json'
        response = new_test.to_json
      when 'application/x-yaml'
        response = json_to_yaml(new_test.to_json)
      else
        halt 415
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method update_test_descriptor_id
  # @overload put '/catalogues/tests/:id/?'
  #	Update a Test Descriptor by its ID in JSON or YAML format
  ## Catalogue - UPDATE
  put '/tests/:id/?' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?
      logger.debug "Catalogue: PUT /v2/tests/#{params[:id]}"

      #Delete key "captures" if present
      params.delete(:captures) if params.key?(:captures)

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)

      # Check for special case (:status param == <new_status>)
      if keyed_params.key?(:status)
        # Do update of Descriptor status -> update_test_status
        logger.info "Catalogue: entered PUT /v2/tests/#{query_string}"

        # Validate Test
        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          test = Testd.find_by({ '_id' => params[:id] })
          puts 'TESTD is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This TESTD does not exists'
        end

        #Validate new status
        valid_status = %w(active inactive delete)
        if valid_status.include? keyed_params[:status]
          # Update to new status
          begin
            test.update_attributes(status: keyed_params[:status])
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
            # When updating a Test Descriptor, the json object sent to API must contain just data inside
            # of the test descriptor, without the json field testd: before
            test, errors = parse_yaml(request.body.read)
            halt 400, errors.to_json if errors

            # Translate from YAML format to JSON format
            new_test_json = yaml_to_json(test)

            # Validate JSON format
            new_test, errors = parse_json(new_test_json)
            halt 400, errors.to_json if errors

          else
            # Compatibility support for JSON content-type
            # Parses and validates JSON format
            new_test, errors = parse_json(request.body.read)
            halt 400, errors.to_json if errors
        end

        # Validate TEST
        # Check if mandatory fields Vendor, Name, Version are included
        json_error 400, 'ERROR: TEST Vendor not found' unless new_test.has_key?('vendor')
        json_error 400, 'ERROR: TEST Name not found' unless new_test.has_key?('name')
        json_error 400, 'ERROR: TEST Version not found' unless new_test.has_key?('version')

        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          test = Testd.find_by({ '_id' => params[:id] })
          puts 'TESTD is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The TESTD ID #{params[:id]} does not exist"
        end

        # Check if Test Descriptor already exists in the catalogue by name, vendor and version
        begin
          test = Testd.find_by({ 'testd.name' => new_test['name'], 'testd.vendor' => new_test['vendor'],
                               'testd.version' => new_test['version'] })
          json_return 200, 'Duplicated TEST Name, Vendor and Version'
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
        new_testd = {}
        new_testd['_id'] = SecureRandom.uuid # Unique UUIDs per TESTD entries
        new_testd['testd'] = new_test
        new_testd['status'] = 'active'
        new_testd['signature'] = nil
        new_testd['md5'] = checksum new_test.to_s
        new_testd['username'] = username

        # First, Refresh dictionary about the new entry
        update_entr_dict(new_testd, :testd)

        begin
          new_test = Testd.create!(new_testd)
        rescue Moped::Errors::OperationFailure => e
          json_return 200, 'Duplicated TEST ID' if e.message.include? 'E11000'
        end
        logger.debug "Catalogue: leaving PUT /v2/tests/#{params[:id]}\" with TESTD #{new_test}"

        response = ''
        case request.content_type
          when 'application/json'
            response = new_test.to_json
          when 'application/x-yaml'
            response = json_to_yaml(new_test.to_json)
          else
            halt 415
        end
        halt 200, {'Content-type' => request.content_type}, response
      end
    end
    logger.debug "Catalogue: leaving PUT /v2/tests/#{params[:id]} with 'No TEST ID specified'"
    json_error 400, 'No TEST ID specified'
  end

  # @method delete_testd_sp_test
  # @overload delete '/tests/?'
  #	Delete a TEST by vendor, name and version
  delete '/tests/?' do
    logger.info "Catalogue: entered DELETE /v2/tests?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    unless keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      begin
        test = Testd.find_by({ 'testd.vendor' => keyed_params[:vendor], 'testd.name' => keyed_params[:name],
                            'testd.version' => keyed_params[:version] })
        puts 'TEST is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The TESTD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
      logger.debug "Catalogue: leaving DELETE /v2/tests?#{query_string}\" with TESTD #{test}"
      # Delete entry in dict mapping
      del_ent_dict(test, :testd)
      test.destroy
      halt 200, 'OK: TESTD removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/tests?#{query_string} with 'No TESTD Vendor, Name, Version specified'"
    json_error 400, 'No TESTD Vendor, Name, Version specified'
  end

  # @method delete_testd_sp_test_id
  # @overload delete '/catalogues/tests/:id/?'
  #	  Delete a TEST Descriptor by its ID
  #	  @param :id [Symbol] id TEST ID
  # Delete a TEST by uuid
  delete '/tests/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: DELETE /v2/tests/#{params[:id]}"
      begin
        test = Testd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The TESTD ID #{params[:id]} does not exist" unless test
      end
      logger.debug "Catalogue: leaving DELETE /v2/tests/#{params[:id]}\" with TESTD #{test}"
      # Delete entry in dict mapping
      del_ent_dict(test, :testd)
      test.destroy
      halt 200, 'OK: TESTD removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/tests/#{params[:id]} with 'No TESTD ID specified'"
    json_error 400, 'No TESTD ID specified'
  end
end
