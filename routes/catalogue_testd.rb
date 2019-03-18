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
  require 'unirest'

  # Fetch Decision Support URL
  tngVnvDsm = ENV.fetch('TNG_VNV_DSM_URL','http://localhost:4010/api')

  # @method get_test_descriptors
  # @overload get '/catalogues/tests/?'
  #	Returns a list of Test Descriptors
  # -> List many descriptors
  get '/tests/?' do
    params['page_number'] ||= DEFAULT_PAGE_NUMBER
    params['page_size'] ||= DEFAULT_PAGE_SIZE

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Logger details
    operation = "GET /v2/tests?#{query_string}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

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
    tests = []
    # Check for special case (:version param == last)
    if keyed_params.key?(:'testd.version') && keyed_params[:'testd.version'] == 'last'
      # Do query for last version -> get_testd_test_vendor_last_version
      keyed_params.delete(:'testd.version')

      tests = Testd.where((keyed_params)).sort({ 'testd.version' => -1 }) #.limit(1).first()

      if tests && tests.size.to_i > 0
        logger.cust_debug(component: component, operation: operation, message: "TESTDs found #{tests}")

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
        logger.cust_debug(component: component, operation: operation, message: "'No TESTDs were found")
        tests_list = []

      end
      tests = apply_limit_and_offset(tests_list, page_number=params[:page_number], page_size=params[:page_size])

    else
      # Do the query
      keyed_params = parse_keys_dict(:testd, keyed_params)
      tests = Testd.where(keyed_params)

      # Set total count for results
      headers 'Record-Count' => tests.count.to_s
      if tests && tests.size.to_i > 0
        logger.cust_debug(component: component, operation: operation, message: "TESTDs found #{tests}")
        # Paginate results
        tests = tests.paginate(page_number: params[:page_number], page_size: params[:page_size])
      else
        logger.cust_debug(component: component, operation: operation, message: "'No TESTDs were found")
      end
    end
    logger.cust_info(status: 200,start_stop:'STOP', message: "Ended at #{Time.now.utc}",  component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

    response = ''
    response = case request.content_type
      when 'application/json'
        tests.to_json
      else
        json_to_yaml(tests.to_json)
               end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method get_tests_id
  # @overload get '/catalogues/tests/:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] id TEST ID
  # Show a Test Descriptor by internal ID (uuid)
  get '/tests/:id/?' do

    # Logger details
    operation = "GET /v2/tests?#{params[:id]}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?
      begin
        test = Testd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The TESTD ID #{params[:id]} does not exist", component, operation, time_req_begin unless test
      end
      logger.cust_debug(component: component, operation: operation, message: "TESTD found #{test}")
      logger.cust_info(status: 200,start_stop:'STOP', message: "Ended at #{Time.now.utc}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

      response = ''
      response = case request.content_type
        when 'application/json'
          test.to_json
        else
          json_to_yaml(test.to_json)
                 end
      halt 200, {'Content-type' => request.content_type}, response

    end
    logger.cust_debug(component: component, operation: operation, message: "No TESTD ID specified")
    json_error 400, 'No TESTD ID specified', component, operation, time_req_begin
  end

  # @method post_tests
  # @overload post '/catalogues/tests'
  # Post a Test Descriptor in JSON or YAML format
  post '/tests' do

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Logger details
    operation = "POST /v2/tests"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a Test Descriptor, the json object sent to API must contain just data inside
        # of the test descriptor, without the json field testd: before
        test, errors = parse_yaml(request.body.read)
        json_error 400, errors, component, operation, time_req_begin if errors

        # Translate from YAML format to JSON format
        new_test_json = yaml_to_json(test)

        # Validate JSON format
        new_test, errors = parse_json(new_test_json)
        json_error 400, errors, component, operation, time_req_begin if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_test, errors = parse_json(request.body.read)
        json_error 400, errors, component, operation, time_req_begin if errors
    end

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Validate Test Descriptor
    json_error 400, 'TEST Vendor not found', component, operation, time_req_begin unless new_test.has_key?('vendor')
    json_error 400, 'TEST Name not found', component, operation, time_req_begin unless new_test.has_key?('name')
    json_error 400, 'TEST Version not found', component, operation, time_req_begin unless new_test.has_key?('version')

    # Comment for file re-usage. Introduce the reference counting of package
    # Check if Test Descriptor already exists in the catalogue by name, vendor and version
    begin
      test = Testd.find_by({ 'testd.name' => new_test['name'], 'testd.vendor' => new_test['vendor'],
                           'testd.version' => new_test['version'] })
      test.update_attributes(pkg_ref: test['pkg_ref'] + 1)
      response = ''
      logger.cust_info(status: 200, start_stop: 'STOP',message: "Update reference to #{test['pkg_ref']}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")
      response = case request.content_type
        when 'application/json'
          test.to_json
        else
          json_to_yaml(test.to_json)
                 end
      halt 200, {'Content-type' => request.content_type}, response
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end


    # Check if Test Descriptor has an ID (it should not) and if it already exists in the catalogue
    begin
      test = Testd.find_by({ '_id' => new_test['_id'] })
      json_error 409, 'Duplicated TEST ID', component, operation, time_req_begin
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    username = if keyed_params.key?(:username)
      keyed_params[:username]
    else
      nil
               end

    # Save to DB
    new_testd = {}
    new_testd['testd'] = new_test
    # Generate the UUID for the descriptor
    new_testd['_id'] = SecureRandom.uuid
    new_testd['status'] = 'active'
    new_testd['pkg_ref'] = 1
    new_testd['signature'] = nil
    new_testd['md5'] = checksum new_test.to_s
    new_testd['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_testd, :testd)

    # Send an asynchronous HTTP request to Decision Support Microservice
    unless username.nil?
      response = Unirest.post tngVnvDsm + "/tests/#{username}/#{new_testd['_id']}",
                            headers: { "Content-type" => "application/json" } { |response|
      response.code # Status code
      response.headers # Response headers
      response.body # Parsed body
      response.raw_body # Unparsed body
      }
    end

    logger.cust_debug(component: component, operation: operation, message: "Sent POST request to #{tngVnvDsm}/tests/#{username}/#{new_testd['_id']}")
    begin
      test = Testd.create!(new_testd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated TEST ID', component, operation, time_req_begin if e.message.include? 'E11000'
    end
    logger.cust_info(status: 201, start_stop: 'STOP', message: "New TEST Descriptor has been added", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

    response = ''
    response = case request.content_type
      when 'application/json'
        test.to_json
      else
        json_to_yaml(test.to_json)
               end
    halt 201, {'Content-type' => request.content_type}, response
  end

  # @method update_test_descriptors
  # @overload put '/tests/?'
  # Update a Test Descriptor by vendor, name and version in JSON or YAML format
  ## Catalogue - UPDATE
  put '/tests/?' do

    # Logger details
    operation = "PUT /v2/tests?#{query_string}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Return if params are empty
    json_error 400, 'Update parameters are null', component, operation, time_req_begin if keyed_params.empty?

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a Test Descriptor, the json object sent to API must contain just data inside
        # of the test descriptor, without the json field testd: before
        test, errors = parse_yaml(request.body.read)
        json_error 400, errors, component, operation, time_req_begin if errors

        # Translate from YAML format to JSON format
        new_test_json = yaml_to_json(test)

        # Validate JSON format
        new_test, errors = parse_json(new_test_json)
        json_error 400, errors, component, operation, time_req_begin if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_test, errors = parse_json(request.body.read)
        json_error 400, errors, component, operation, time_req_begin if errors
    end

    # Validate NS
    # Check if mandatory fields Vendor, Name, Version are included
    json_error 400, 'TEST Vendor not found', component, operation, time_req_begin unless new_test.has_key?('vendor')
    json_error 400, 'TEST Name not found', component, operation, time_req_begin unless new_test.has_key?('name')
    json_error 400, 'TEST Version not found', component, operation, time_req_begin unless new_test.has_key?('version')

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
        test = Testd.find_by({ 'testd.vendor' => keyed_params[:vendor], 'testd.name' => keyed_params[:name],
                            'testd.version' => keyed_params[:version] })
        logger.cust_debug(component: component, operation: operation, message: "TEST Descriptor is found")
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The TESTD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist", component, operation, time_req_begin
      end
    end
    # Check if Test Descriptor already exists in the catalogue by Name, Vendor and Version
    begin
      test = Testd.find_by({ 'testd.name' => new_test['name'], 'testd.vendor' => new_test['vendor'],
                           'testd.version' => new_test['version'] })
      json_return 200, 'Duplicated TEST Name, Vendor and Version', component, operation, time_req_begin
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    username = if keyed_params.key?(:username)
      keyed_params[:username]
    else
      nil
               end

    # Update to new version
    puts 'Updating...'
    new_testd = {}
    new_testd['_id'] = SecureRandom.uuid # Unique UUIDs per Test Descriptor entries
    new_testd['testd'] = new_test
    new_testd['status'] = 'active'
    new_testd['pkg_ref'] = 1
    new_testd['signature'] = nil
    new_testd['md5'] = checksum new_test.to_s
    new_testd['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_testd, :testd)

    begin
      new_test = Testd.create!(new_testd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated TEST ID', component, operation, time_req_begin if e.message.include? 'E11000'
    end
    logger.cust_debug(component: component, operation: operation, message: "TESTD #{new_test}")
    logger.cust_info(status: 200, start_stop: 'STOP', message: "Ended at #{Time.now.utc}" , component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

    response = ''
    response = case request.content_type
      when 'application/json'
        new_test.to_json
      else
        json_to_yaml(new_test.to_json)
               end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method update_test_descriptor_id
  # @overload put '/catalogues/tests/:id/?'
  #	Update a Test Descriptor by its ID in JSON or YAML format
  ## Catalogue - UPDATE
  put '/tests/:id/?' do

    # Logger details
    operation = "PUT /v2/tests/#{params[:id]}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?

      #Delete key "captures" if present
      params.delete(:captures) if params.key?(:captures)

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)

      # Check for special case (:status param == <new_status>)
      if keyed_params.key?(:status)
        # Do update of Descriptor status -> update_test_status
        logger.cust_debug(component: component, operation: operation, message: "entered PUT /v2/tests/#{query_string}")

        # Validate Test
        # Retrieve stored version
        begin
          test = Testd.find_by({ '_id' => params[:id] })
          logger.cust_debug(component: component, operation: operation, message: "TESTD is found")
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This TESTD does not exists', component, operation, time_req_begin
        end

        #Validate new status
        valid_status = %w(active inactive delete)
        if valid_status.include? keyed_params[:status]
          # Update to new status
          begin
            test.update_attributes(status: keyed_params[:status])
          rescue Moped::Errors::OperationFailure => e
            json_error 400, 'Operation failed', component, operation, time_req_begin
          end
        else
          json_error 400, "Invalid new status #{keyed_params[:status]}", component, operation, time_req_begin
        end
        json_return 200, "Status updated to {#{query_string}}", component, operation, time_req_begin

      else
        # Compatibility support for YAML content-type
        case request.content_type
          when 'application/x-yaml'
            # Validate YAML format
            # When updating a Test Descriptor, the json object sent to API must contain just data inside
            # of the test descriptor, without the json field testd: before
            test, errors = parse_yaml(request.body.read)
            json_error 400, errors, component, operation, time_req_begin if errors

            # Translate from YAML format to JSON format
            new_test_json = yaml_to_json(test)

            # Validate JSON format
            new_test, errors = parse_json(new_test_json)
            json_error 400, errors, component, operation, time_req_begin if errors

          else
            # Compatibility support for JSON content-type
            # Parses and validates JSON format
            new_test, errors = parse_json(request.body.read)
            json_error 400, errors, component, operation, time_req_begin if errors
        end

        # Validate TEST
        # Check if mandatory fields Vendor, Name, Version are included
        json_error 400, 'TEST Vendor not found', component, operation, time_req_begin unless new_test.has_key?('vendor')
        json_error 400, 'TEST Name not found', component, operation, time_req_begin unless new_test.has_key?('name')
        json_error 400, 'TEST Version not found', component, operation, time_req_begin unless new_test.has_key?('version')

        # Retrieve stored version
        begin
          test = Testd.find_by({ '_id' => params[:id] })
          logger.cust_debug(component: component, operation: operation, message: "TESTD is found")
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The TESTD ID #{params[:id]} does not exist", component, operation, time_req_begin
        end

        # Check if Test Descriptor already exists in the catalogue by name, vendor and version
        begin
          test = Testd.find_by({ 'testd.name' => new_test['name'], 'testd.vendor' => new_test['vendor'],
                               'testd.version' => new_test['version'] })
          json_return 200, 'Duplicated TEST Name, Vendor and Version', component, operation, time_req_begin
        rescue Mongoid::Errors::DocumentNotFound => e
          # Continue
        end

        username = if keyed_params.key?(:username)
          keyed_params[:username]
        else
          nil
                   end

        # Update to new version
        puts 'Updating...'
        new_testd = {}
        new_testd['_id'] = SecureRandom.uuid # Unique UUIDs per TESTD entries
        new_testd['testd'] = new_test
        new_testd['status'] = 'active'
        new_testd['pkg_ref'] = 1
        new_testd['signature'] = nil
        new_testd['md5'] = checksum new_test.to_s
        new_testd['username'] = username

        # First, Refresh dictionary about the new entry
        update_entr_dict(new_testd, :testd)

        begin
          new_test = Testd.create!(new_testd)
        rescue Moped::Errors::OperationFailure => e
          json_return 200, 'Duplicated TEST ID', component, operation, time_req_begin if e.message.include? 'E11000'
        end

        logger.cust_info(status: 200, start_stop: 'STOP', message:"TESTD #{new_test}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

        response = ''
        response = case request.content_type
          when 'application/json'
            new_test.to_json
          else
            json_to_yaml(new_test.to_json)
                   end
        halt 200, {'Content-type' => request.content_type}, response
      end
    end
    logger.cust_debug(component: component, operation: operation, message: "No TEST ID specified")
    json_error 400, 'No TEST ID specified', component, operation, time_req_begin
  end

  # @method delete_testd_sp_test
  # @overload delete '/tests/?'
  #	Delete a TEST by vendor, name and version
  delete '/tests/?' do

    # Logger details
    operation = "DELETE /v2/tests?#{query_string}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    unless keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      begin
        test = Testd.find_by({ 'testd.vendor' => keyed_params[:vendor], 'testd.name' => keyed_params[:name],
                            'testd.version' => keyed_params[:version] })
        logger.cust_debug(component: component, operation: operation, message: "TEST is found")
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The TESTD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist", component, operation, time_req_begin
      end
      logger.cust_debug(component: component, operation: operation, message: "TESTD #{test}")

      if test['pkg_ref'] == 1
        # Referenced only once. Delete in this case
        # Delete entry in dict mapping
        del_ent_dict(test, :testd)
        test.destroy
        json_result 200, 'TESTD removed', component, operation, time_req_begin
      else
        # Referenced above once. Decrease counter
        test.update_attributes(pkg_ref: test['pkg_ref'] - 1)
        json_result 200, "TESTD referenced => #{test['pkg_ref']}", component, operation, time_req_begin
      end
    end
    logger.cust_debug(component: component, operation: operation, message: "No TESTD Vendor, Name, Version specified")
    json_error 400, 'No TESTD Vendor, Name, Version specified', component, operation, time_req_begin
  end

  # @method delete_testd_sp_test_id
  # @overload delete '/catalogues/tests/:id/?'
  #	  Delete a TEST Descriptor by its ID
  #	  @param :id [Symbol] id TEST ID
  # Delete a TEST by uuid
  delete '/tests/:id/?' do

    # Logger details
    operation = "DELETE /v2/tests/#{params[:id]}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    unless params[:id].nil?
      begin
        test = Testd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The TESTD ID #{params[:id]} does not exist", component, operation, time_req_begin unless test
      end
      logger.cust_debug(component: component, operation: operation, message: "TESTD #{test}")

      if test['pkg_ref'] == 1
        # Referenced only once. Delete in this case
        # Delete entry in dict mapping
        del_ent_dict(test, :testd)
        test.destroy
        # Send an asynchronous HTTP request to Decision Support Microservice
        response = Unirest.delete tngVnvDsm + "/tests/#{test['_id']}",
                                  headers: { "Content-type" => "application/json" } { |response|
          response.code # Status code
          response.headers # Response headers
          response.body # Parsed body
          response.raw_body # Unparsed body
        }
        logger.cust_debug(component: component, operation: operation, message: "Sent DELETE request to #{tngVnvDsm}/tests/#{test['_id']}")
        json_return 200, 'TESTD removed', component, operation, time_req_begin
      else
        # Referenced above once. Decrease counter
        test.update_attributes(pkg_ref: test['pkg_ref'] - 1)
        json_return 200, "TESTD referenced => #{test['pkg_ref']}", component, operation, time_req_begin
      end

    end
    logger.debug "Catalogue: leaving DELETE /v2/tests/#{params[:id]} with 'No TESTD ID specified'"
    json_error 400, 'No TESTD ID specified'
  end
end
