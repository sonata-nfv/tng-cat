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

  ### PD API METHODS ###

  # @method get_packages
  # @overload get '/catalogues/packages/?'
  #	Returns a list of all Packages
  # -> List many descriptors
  get '/packages/?' do
    params['page_number'] ||= DEFAULT_PAGE_NUMBER
    params['page_size'] ||= DEFAULT_PAGE_SIZE

    # uri = Addressable::URI.new
    # uri.query_values = params
    # puts 'params', params
    # puts 'query_values', uri.query_values
    logger.info "Catalogue: entered GET /packages?#{query_string}"

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

    # Get rid of :page_number and :page_size
    [:page_number, :page_size].each { |k| keyed_params.delete(k) }
    # puts 'keyed_params(1)', keyed_params

    # Check for special case (:version param == last)
    if keyed_params.key?(:version) && keyed_params[:version] == 'last'
      # Do query for last version -> get_nsd_ns_vendor_last_version

      keyed_params.delete(:version)
      # puts 'keyed_params(2)', keyed_params

      pks = Package.where((keyed_params)).sort( 'version' => -1 ) #.limit(1).first()
      logger.info "Catalogue: PDs=#{pks}"
      # pks = pks.sort({"version" => -1})
      # puts 'pks: ', pks.to_json

      if pks && pks.size.to_i > 0
        logger.info "Catalogue: leaving GET /packages?#{query_string} with #{pks}"

        # Paginate results
        # pks = pks.paginate(:page_number => params[:page_number], :page_size => params[:page_size]).sort({"version" => -1})

        pks_list = []
        checked_list = []

        pks_name_vendor = Pair.new(pks.first.name, pks.first.vendor)
        # p 'pks_name_vendor:', [pks_name_vendor.one, pks_name_vendor.two]
        checked_list.push(pks_name_vendor)
        pks_list.push(pks.first)

        pks.each do |pd|
          # p 'Comparison: ', [pd.name, pd.vendor].to_s + [pks_name_vendor.one, pks_name_vendor.two].to_s
          if (pd.name != pks_name_vendor.one) || (pd.vendor != pks_name_vendor.two)
            pks_name_vendor = Pair.new(pd.name, pd.vendor)
          end
          pks_list.push(pd) unless checked_list.any? { |pair| pair.one == pks_name_vendor.one &&
              pair.two == pks_name_vendor.two }
          checked_list.push(pks_name_vendor)
        end

        # puts 'pks_list:', pks_list.each {|p| p p.name, p.vendor}
      else
        # logger.error "ERROR: 'No PDs were found'"
        logger.info "Catalogue: leaving GET /packages?#{query_string} with 'No PDs were found'"
        # json_error 404, "No PDs were found"
        pks_list = []
      end
      # pks = pks_list.paginate(:page => params[:page_number], :per_page =>params[:page_size])
      pks = apply_limit_and_offset(pks_list, params[:page_number], params[:page_size])

    else
      # Do the query
      pks = Package.where(keyed_params)
      logger.info "Catalogue: PDs=#{pks}"
      # puts pks.to_json
      if pks && pks.size.to_i > 0
        logger.info "Catalogue: leaving GET /packages?#{query_string} with #{pks}"

        # Paginate results
        pks = pks.paginate(page_number: params[:page_number], page_size: params[:page_size])

      else
        logger.info "Catalogue: leaving GET /packages?#{query_string} with 'No PDs were found'"
        # json_error 404, "No PDs were found"
      end
    end

    response = ''
    case request.content_type
      when 'application/json'
        response = pks.to_json
      when 'application/x-yaml'
        response = json_to_yaml(pks.to_json)
      else
        halt 415
    end
    halt 200, response
  end

  # @method get_packages_package_id
  # @overload get '/catalogues/packages:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] package_uuid Package id
  # Show a Package by uuid
  get '/packages/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: GET /packages/#{params[:id]}"

      begin
        pks = Package.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The PD ID #{params[:id]} does not exist" unless pks
      end
      logger.debug "Catalogue: leaving GET /packages/#{params[:id]}\" with PD #{pks}"

      response = ''
      case request.content_type
        when 'application/json'
          response = pks.to_json
        when 'application/x-yaml'
          response = json_to_yaml(pks.to_json)
        else
          halt 415
      end
      halt 200, response

    end
    logger.debug "Catalogue: leaving GET /packages/#{params[:id]} with 'No PD ID specified'"
    json_error 400, 'No PD ID specified'
  end

  # @method post_package
  # @overload post '/catalogues/packages'
  # Post a Package in JSON or YAML format
  post '/packages' do
    # A bit more work as it needs to parse the package descriptor to get GROUP, NAME, and VERSION.
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a PD, the json object sent to API must contain just data inside
        # of the pd, without the json field pd: before
        pks, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_pks_json = yaml_to_json(pks)

        # Validate JSON format
        new_pks, errors = parse_json(new_pks_json)
        # puts 'pks: ', new_pks.to_json
        # puts 'new_pks id', new_pks['_id'].to_json
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_pks, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    # Validate NS
    json_error 400, 'ERROR: Package Vendor not found' unless new_pks.has_key?('vendor')
    json_error 400, 'ERROR: Package Name not found' unless new_pks.has_key?('name')
    json_error 400, 'ERROR: Package Version not found' unless new_pks.has_key?('version')

    # --> Validation disabled
    # Validate PD
    # begin
    #	  postcurb settings.nsd_validator + '/nsds', ns.to_json, :content_type => :json
    # rescue => e
    #	  halt 500, {'Content-Type' => 'text/plain'}, "Validator mS unrechable."
    # end

    # Check if PD already exists in the catalogue by name, vendor and version
    begin
      pks = Package.find_by('name' => new_pks['name'], 'vendor' => new_pks['vendor'], 'version' => new_pks['version'])
      json_return 200, 'Duplicated Package Name, Vendor and Version'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end
    # Check if PD has an ID (it should not) and if it already exists in the catalogue
    begin
      pks = Package.find_by('_id' => new_pks['_id'])
      json_return 200, 'Duplicated Package ID'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    # Save to DB
    begin
      # Generate the UUID for the descriptor
      new_pks['_id'] = SecureRandom.uuid
      new_pks['status'] = 'active'
      pks = Package.create!(new_pks)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated Package ID' if e.message.include? 'E11000'
    end

    puts 'New Package has been added'
    response = ''
    case request.content_type
      when 'application/json'
        response = pks.to_json
      when 'application/x-yaml'
        response = json_to_yaml(pks.to_json)
      else
        halt 415
    end
    halt 201, response
  end

  # @method update_package_group_name_version
  # @overload put '/catalogues/packages/vendor/:package_group/name/:package_name/version/:package_version
  #	Update a Package vendor, name and version in JSON or YAML format
  ## Catalogue - UPDATE
  put '/packages/?' do
    # uri = Addressable::URI.new
    # uri.query_values = params
    # puts 'params', params
    # puts 'query_values', uri.query_values
    logger.info "Catalogue: entered PUT /packages?#{query_string}"

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
        # When updating a PD, the json object sent to API must contain just data inside
        # of the pd, without the json field pd: before
        pks, errors = parse_yaml(request.body.read)
        halt 400, errors.to_json if errors

        # Translate from YAML format to JSON format
        new_pks_json = yaml_to_json(pks)

        # Validate JSON format
        new_pks, errors = parse_json(new_pks_json)
        # puts 'pks: ', new_pks.to_json
        # puts 'new_pks id', new_pks['_id'].to_json
        halt 400, errors.to_json if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_pks, errors = parse_json(request.body.read)
        halt 400, errors.to_json if errors
    end

    # Validate Package
    # Check if same vendor, Name, Version do already exists in the database
    json_error 400, 'ERROR: Package Vendor not found' unless new_pks.has_key?('vendor')
    json_error 400, 'ERROR: Package Name not found' unless new_pks.has_key?('name')
    json_error 400, 'ERROR: Package Version not found' unless new_pks.has_key?('version')

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
        pks = Package.find_by('vendor' => keyed_params[:vendor], 'name' => keyed_params[:name],
                                'version' => keyed_params[:version])
        puts "Package is found #{pks.to_s}"
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The PD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
    end
    # Check if PD already exists in the catalogue by name, group and version
    begin
      pks = Package.find_by('name' => new_pks['name'], 'vendor' => new_pks['vendor'], 'version' => new_pks['version'])
      json_return 200, 'Duplicated PD Name, Vendor and Version'
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    # Update to new version
    puts 'Updating...'
    new_pks['_id'] = SecureRandom.uuid # Unique UUIDs per PD entries
    pd = new_pks

    # --> Validation disabled
    # Validate PD
    # begin
    #	postcurb settings.nsd_validator + '/nsds', nsd.to_json, :content_type => :json
    # rescue => e
    #	logger.error e.response
    #	return e.response.code, e.response.body
    # end

    begin
      new_pks = Package.create!(pd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated Package ID' if e.message.include? 'E11000'
    end
    logger.debug "Catalogue: leaving PUT /packages?#{query_string}\" with PD #{new_pks}"

    response = ''
    case request.content_type
      when 'application/json'
        response = new_pks.to_json
      when 'application/x-yaml'
        response = json_to_yaml(new_pks.to_json)
      else
        halt 415
    end
    halt 200, response
  end

  # @method update_package_id
  # @overload put '/catalogues/packages/:id/?'
  #	Update a Package in JSON or YAML format
  ## Catalogue - UPDATE
  put '/packages/:id/?' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?
      logger.debug "Catalogue: PUT /packages/#{params[:id]}"

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)
      # puts 'keyed_params', keyed_params

      # Check for special case (:status param == <new_status>)
      if keyed_params.key?(:status)
        # Do update of Descriptor status -> update_ns_status
        # uri = Addressable::URI.new
        # uri.query_values = params
        logger.info "Catalogue: entered PUT /packages/#{query_string}"

        # Validate Package
        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          pks = Package.find_by('_id' => params[:id])
          puts 'Package is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This PD does not exists'
        end

        # Validate new status
        valid_status = %w(active inactive delete)
        if valid_status.include? keyed_params[:status]
          # Update to new status
          begin
            # pks.update_attributes(:status => params[:new_status])
            pks.update_attributes(status: keyed_params[:status])
          rescue Moped::Errors::OperationFailure => e
            json_error 400, 'ERROR: Operation failed'
          end
        else
          json_error 400, "Invalid new status #{keyed_params[:status]}"
        end

        # --> Validation disabled
        # Validate PD
        # begin
        #	  postcurb settings.nsd_validator + '/nsds', nsd.to_json, :content_type => :json
        # rescue => e
        #	  logger.error e.response
        #	  return e.response.code, e.response.body
        #end

        halt 200, "Status updated to {#{query_string}}"

      # Check for special case (:sonp_uuid param == <uuid>)
      elsif keyed_params.key?(:sonp_uuid)
        # Do update of Package meta-data to include son-package uuid
        # uri = Addressable::URI.new
        # uri.query_values = params
        logger.info "Catalogue: entered PUT /packages/#{query_string}"

        # Validate Package
        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          pks = Package.find_by('_id' => params[:id])
          puts 'Package is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This PD does not exists'
        end

        # Validate son-package uuid
        begin
          puts 'Searching ' + params[:sonp_uuid].to_s
          sonp = FileContainer.find_by('_id' => params[:sonp_uuid])
          p 'Filename: ', sonp['package_name']
          puts 'son-package is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'Submitted son-package UUID not exists'
        end

        # Add new son-package uuid field
        begin
          pks.update_attributes(son_package_uuid: keyed_params[:sonp_uuid])
        rescue Moped::Errors::OperationFailure => e
          json_error 400, 'ERROR: Operation failed'
        end

        halt 200, "PD updated with son-package uuid: #{keyed_params[:sonp_uuid]}"

        # --> Validation disabled
        # Validate PD
        # begin
        #	  postcurb settings.nsd_validator + '/nsds', nsd.to_json, :content_type => :json
        # rescue => e
        #	  logger.error e.response
        #	  return e.response.code, e.response.body
        #end

      else
        # Compatibility support for YAML content-type
        case request.content_type
          when 'application/x-yaml'
            # Validate YAML format
            # When updating a NSD, the json object sent to API must contain just data inside
            # of the nsd, without the json field nsd: before
            pks, errors = parse_yaml(request.body.read)
            halt 400, errors.to_json if errors

            # Translate from YAML format to JSON format
            new_ns_json = yaml_to_json(pks)

            # Validate JSON format
            new_pks, errors = parse_json(new_ns_json)
            # puts 'pks: ', new_pks.to_json
            # puts 'new_pks id', new_pks['_id'].to_json
            halt 400, errors.to_json if errors

          else
            # Compatibility support for JSON content-type
            # Parses and validates JSON format
            new_pks, errors = parse_json(request.body.read)
            halt 400, errors.to_json if errors
        end

        # Validate Package
        # Check if same vendor, Name, Version do already exists in the database
        json_error 400, 'ERROR: Package Vendor not found' unless new_pks.has_key?('vendor')
        json_error 400, 'ERROR: Package Name not found' unless new_pks.has_key?('name')
        json_error 400, 'ERROR: Package Version not found' unless new_pks.has_key?('version')

        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          pks = Package.find_by('_id' => params[:id])
          puts 'Package is found'
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The PD ID #{params[:id]} does not exist"
        end

        # Check if Package already exists in the catalogue by name, vendor and version
        begin
          pks = Package.find_by('name' => new_pks['name'], 'vendor' => new_pks['vendor'],
                                  'version' => new_pks['version'])
          json_return 200, 'Duplicated Package Name, Vendor and Version'
        rescue Mongoid::Errors::DocumentNotFound => e
          # Continue
        end

        # Update to new version
        puts 'Updating...'
        new_pks['_id'] = SecureRandom.uuid
        pd = new_pks

        # --> Validation disabled
        # Validate PD
        # begin
        #	  postcurb settings.nsd_validator + '/nsds', nsd.to_json, :content_type => :json
        # rescue => e
        #	  logger.error e.response
        #	  return e.response.code, e.response.body
        # end

        begin
          new_pks = Package.create!(pd)
        rescue Moped::Errors::OperationFailure => e
          json_return 200, 'Duplicated Package ID' if e.message.include? 'E11000'
        end
        logger.debug "Catalogue: leaving PUT /packages/#{params[:id]}\" with PD #{new_pks}"

        response = ''
        case request.content_type
          when 'application/json'
            response = new_pks.to_json
          when 'application/x-yaml'
            response = json_to_yaml(new_pks.to_json)
          else
            halt 415
        end
        halt 200, response
      end
    end
    logger.debug "Catalogue: leaving PUT /packages/#{params[:id]} with 'No PD ID specified'"
    json_error 400, 'No PD ID specified'
  end

  # @method delete_pd_package_group_name_version
  # @overload delete '/catalogues/packages/vendor/:package_group/name/:package_name/version/:package_version'
  #	Delete a PD by group, name and version
  delete '/packages/?' do
    # uri = Addressable::URI.new
    # uri.query_values = params
    # puts 'params', params
    # puts 'query_values', uri.query_values
    logger.info "Catalogue: entered DELETE /packages?#{query_string}"

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)
    # puts 'keyed_params', keyed_params

    unless keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      begin
        pks = Package.find_by('vendor' => keyed_params[:vendor], 'name' => keyed_params[:name],
                                'version' => keyed_params[:version])
        puts 'Package is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The PD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
      logger.debug "Catalogue: leaving DELETE /packages?#{query_string}\" with PD #{pks}"
      pks.destroy
      halt 200, 'OK: PD removed'
    end
    logger.debug "Catalogue: leaving DELETE /packages?#{query_string} with 'No PD Vendor, Name, Version specified'"
    json_error 400, 'No PD Vendor, Name, Version specified'
  end

  # @method delete_pd_package_id
  # @overload delete '/catalogues/packages/:id/?'
  #	  Delete a PD by its ID
  #	  @param :id [Symbol] identifier for PD
  # Delete a PD by uuid
  delete '/packages/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: DELETE /packages/#{params[:id]}"
      begin
        pks = Package.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The PD ID #{params[:id]} does not exist" unless pks
      end
      logger.debug "Catalogue: leaving DELETE /packages/#{params[:id]}\" with PD #{pks}"
      pks.destroy
      halt 200, 'OK: PD removed'
    end
    logger.debug "Catalogue: leaving DELETE /packages/#{params[:id]} with 'No PD ID specified'"
    json_error 400, 'No PD ID specified'
  end
end

class CatalogueV2 < SonataCatalogue
  ### PD API METHODS ###

  # @method get_packages
  # @overload get '/catalogues/packages/?'
  #	Returns a list of all Packages
  # -> List many descriptors
  get '/packages/?' do
    params['page_number'] ||= DEFAULT_PAGE_NUMBER
    params['page_size'] ||= DEFAULT_PAGE_SIZE

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Logger details
    operation = "GET /v2/packages?#{query_string}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    # Split keys in meta_data and data
    # Then transform 'string' params Hash into keys
    keyed_params = add_descriptor_level('pd', params)

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
    if keyed_params.key?(:'pd.version') && keyed_params[:'pd.version'] == 'last'
      # Do query for last version -> get_pd_package_vendor_last_version
      keyed_params.delete(:'pd.version')

      pks = Pkgd.where((keyed_params)).sort( 'pd.version' => -1 ) #.limit(1).first()
      # pks = pks.sort({"version" => -1})

      if pks && pks.size.to_i > 0
        logger.cust_debug(component: component, operation: operation, message: "PDs found #{pks}")

        pks_list = []
        checked_list = []

        pks_name_vendor = Pair.new(pks.first.pd['name'], pks.first.pd['vendor'])
        checked_list.push(pks_name_vendor)
        pks_list.push(pks.first)

        pks.each do |pd|
          if (pd.pd['name'] != pks_name_vendor.one) || (pd.pd['vendor'] != pks_name_vendor.two)
            pks_name_vendor = Pair.new(pd.pd['name'], pd.pd['vendor'])
          end
          pks_list.push(pd) unless checked_list.any? { |pair| pair.one == pks_name_vendor.one &&
              pair.two == pks_name_vendor.two }
          checked_list.push(pks_name_vendor)
        end
        logger.cust_info(status: 200, start_stop: 'STOP', component: component, operation: operation, message: "Ended at #{Time.now.utc}", time_elapsed: "#{Time.now.utc - time_req_begin }")

      else
        logger.cust_info(status: 200, component: component, operation: operation, message: "'No PDs were found'", time_elapsed: "#{Time.now.utc - time_req_begin }")
        pks_list = []
      end
      pks = apply_limit_and_offset(pks_list, page_number=params[:page_number],
                                   page_size=params[:page_size])

    else
      # Do the query
      keyed_params = parse_keys_dict(:pd, keyed_params)
      pks = Pkgd.where(keyed_params)

      # Set total count for results
      headers 'Record-Count' => pks.count.to_s

      if pks && pks.size.to_i > 0
        logger.cust_info(status: 200, component: component, operation: operation, message: "PDs found #{pks}", time_elapsed: "#{Time.now.utc - time_req_begin }")
        # Paginate results
        pks = pks.paginate(page_number: params[:page_number], page_size: params[:page_size])
      else
        logger.cust_info(status: 200, component: component, operation: operation, message: 'No PDs were found', time_elapsed: "#{Time.now.utc - time_req_begin }")
      end
    end

    response = ''
    case request.content_type
      when 'application/json'
        response = pks.to_json
      when 'application/x-yaml'
        response = json_to_yaml(pks.to_json)
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method get_packages_package_id
  # @overload get '/catalogues/packages:id/?'
  #	  GET one specific descriptor
  #	  @param :id [Symbol] package_uuid Package id
  # Show a Package by uuid
  get '/packages/:id/?' do

    # Logger details
    operation = "GET /v2/packages/#{params[:id]}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    unless params[:id].nil?
      begin
        pks = Pkgd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The PD ID #{params[:id]} does not exist", component, operation, time_req_begin unless pks
      end

      logger.cust_debug(component: component, operation: operation, message: "PD found #{pks}")

      response = ''
      case request.content_type
        when 'application/json'
          response = pks.to_json
        when 'application/x-yaml'
          response = json_to_yaml(pks.to_json)
      end
      logger.cust_info(start_stop:'STOP', component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

      halt 200, {'Content-type' => request.content_type}, response

    end
    logger.cust_debug(component: component, operation: operation, message: "No PD ID specified")
    json_error 400, 'No PD ID specified', component, operation, time_req_begin
  end

  # @method get_packages_package_id_files_
  # @overload get '/catalogues/packages/:id/files/?'
  #	  GET all files with the content type referenced in pd
  #	  @param :id [Symbol] package_uuid Package id
  get '/packages/:id/files/?' do


    # Logger details
    operation = "GET /v2/packages/#{params[:id]}/files"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    unless params[:id].nil?
      logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

      begin
        pks = Pkgd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The PD ID #{params[:id]} does not exist", component, operation, time_req_begin unless pks
      end

      response = ''
      case request.content_type
        when 'application/json'
          response = pks['pd']['package_content'].to_json
        when 'application/x-yaml'
          response = json_to_yaml(pks['pd']['package_content'].to_json)
      end
      logger.cust_info(start_stop:'STOP', component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

      halt 200, {'Content-type' => request.content_type}, response
    end
    logger.cust_debug(component: component, operation: operation, message: "No PD ID specified")
    json_error 400, 'No PD ID specified', component, operation, time_req_begin
  end


  # @method get_packages_package_id_files_fileuuid
  # @overload get '/catalogues/packages/:id/files/file_uuid?'
  #	  GET one specific file with the content type referenced in pd
  #	  @param :id [Symbol] package_uuid Package id
  # 	@param :file_uuid [Symbol] file_uuid file id
  get '/packages/:id/files/:file_uuid/?' do

    # Logger details
    operation = "GET /v2/packages/#{params[:id]}/files/#{params[:file_uuid]}}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    unless params[:id].nil?
      logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

      begin
        pks = Pkgd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The PD ID #{params[:id]} does not exist", component, operation, time_req_begin unless pks
      end

      content_type = 'application/octet-stream'
      pks['pd']['package_content'].each do |content|
        content_type = content['content-type'] if content['uuid'] == params[:file_uuid]
      end

      begin
        file = Files.find_by('_id' => params[:file_uuid])
        p 'Filename: ', file['file_name']
        p 'grid_fs_id: ', file['grid_fs_id']
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "File with {uuid => #{params[:file_uuid]}} not found", component, operation, time_req_begin
      end

      grid_fs = Mongoid::GridFs
      grid_file = grid_fs.get(file['grid_fs_id'])

      # Set custom header with Filename
      headers 'Filename' => (file['file_name'].to_s)

      logger.cust_info(start_stop:'STOP', component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")
      halt 200, {'Content-type' => content_type}, grid_file.data

    end
    logger.cust_debug(component: component, operation: operation, message: "No PD ID specified")
    json_error 400, 'No PD ID specified', component, operation, time_req_begin
  end

  # @method post_package
  # @overload post '/catalogues/packages'
  # Post a Package in JSON or YAML format
  post '/packages' do


    # Logger details
    operation = 'POST /v2/packages/'
    component = __method__.to_s
    time_req_begin = Time.now.utc

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')


    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a PD, the json object sent to API must contain just data inside
        # of the pd, without the json field pd: before
        pks, errors = parse_yaml(request.body.read)
        json_error 400, errors.to_json , component, operation, time_req_begin if errors

        # Translate from YAML format to JSON format
        new_pks_json = yaml_to_json(pks)

        # Validate JSON format
        new_pks, errors = parse_json(new_pks_json)
        json_error 400, errors.to_json , component, operation, time_req_begin if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_pks, errors = parse_json(request.body.read)
        json_error 400, errors.to_json , component, operation, time_req_begin if errors
    end

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

    # Validate NS
    json_error 400, 'Package Vendor not found', component, operation, time_req_begin unless new_pks.has_key?('vendor')
    json_error 400, 'Package Name not found', component, operation, time_req_begin unless new_pks.has_key?('name')
    json_error 400, 'Package Version not found', component, operation, time_req_begin unless new_pks.has_key?('version')

    # Check if PD already exists in the catalogue by name, vendor and version
    begin
      pks = Pkgd.find_by('pd.name' => new_pks['name'], 'pd.vendor' => new_pks['vendor'],
                           'pd.version' => new_pks['version'])
      json_error 409, "Duplicate with Package ID => #{pks['_id']}", component, operation, time_req_begin

    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end


    # Check if PD has an ID (it should not) and if it already exists in the catalogue
    begin
      pks = Pkgd.find_by('_id' => new_pks['_id'])
      json_error 409, "Duplicated Package ID => #{pks['_id']}", component, operation, time_req_begin
    rescue Mongoid::Errors::DocumentNotFound => e
      # Continue
    end

    if keyed_params.key?(:username)
      username = keyed_params[:username]
    else
      username = nil
    end

    # Save to DB
    new_pd = {}
    new_pd['pd'] = new_pks

    # Generate the UUID for the descriptor
    new_pd['_id'] = SecureRandom.uuid
    new_pd['status'] = 'active'
    new_pd['signature'] = nil
    new_pd['md5'] = checksum new_pks.to_s
    new_pd['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_pd, :pd)

    begin
      pks = Pkgd.create!(new_pd)
      logger.cust_info(status: 201, start_stop:'STOP', component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated Package ID', component, operation, time_req_begin if e.message.include? 'E11000'
    end

    puts 'New Package has been added'
    response = ''
    case request.content_type
      when 'application/json'
        response = pks.to_json
      when 'application/x-yaml'
        response = json_to_yaml(pks.to_json)
    end

    halt 201, {'Content-type' => request.content_type}, response
  end


  # @method update_package_group_name_version
  # @overload put '/catalogues/packages/vendor/:package_group/name/:package_name/version/:package_version
  #	Update a Package vendor, name and version in JSON or YAML format
  ## Catalogue - UPDATE
  put '/packages/?' do

    # Logger details
    operation = "PUT /v2/packages?#{query_string}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)


    # Return if params are empty
    json_error 400, 'Update parameters are null', component, operation, time_req_begin if keyed_params.empty?

    # Compatibility support for YAML content-type
    case request.content_type
      when 'application/x-yaml'
        # Validate YAML format
        # When updating a PD, the json object sent to API must contain just data inside
        # of the pd, without the json field pd: before
        pks, errors = parse_yaml(request.body.read)
        json_error 400, errors.to_json , component, operation, time_req_begin if errors

        # Translate from YAML format to JSON format
        new_pks_json = yaml_to_json(pks)

        # Validate JSON format
        new_pks, errors = parse_json(new_pks_json)
        json_error 400, errors.to_json , component, operation, time_req_begin if errors

      else
        # Compatibility support for JSON content-type
        # Parses and validates JSON format
        new_pks, errors = parse_json(request.body.read)
        json_error 400, errors.to_json , component, operation, time_req_begin if errors
    end

    # Validate Package
    # Check if mandatory fields Vendor, Name, Version are included
    json_error 400, 'Package Vendor not found', component, operation, time_req_begin unless new_pks.has_key?('vendor')
    json_error 400, 'Package Name not found', component, operation, time_req_begin unless new_pks.has_key?('name')
    json_error 400, 'Package Version not found', component, operation, time_req_begin unless new_pks.has_key?('version')

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
        pks = Pkgd.find_by('pd.vendor' => keyed_params[:vendor], 'pd.name' => keyed_params[:name],
                                'pd.version' => keyed_params[:version])

      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The PD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist", component, operation, time_req_begin
      end
    end


    # Check if PD already exists in the catalogue by Name, Vendor and Version
    begin
      pks = Pkgd.find_by('pd.name' => new_pks['name'], 'pd.vendor' => new_pks['vendor'],
                           'pd.version' => new_pks['version'])
      json_return 200, 'Duplicated PD Name, Vendor and Version', component, operation, time_req_begin
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
    new_pd = {}
    new_pd['_id'] = SecureRandom.uuid # Unique UUIDs per PD entries
    new_pd['pd'] = new_pks
    new_pd['status'] = 'active'
    # new_pd['package_file_id'] = nil
    # new_pd['package_file_name'] = nil
    new_pd['signature'] = nil
    new_pd['md5'] = checksum new_pks.to_s
    new_pd['username'] = username

    # First, Refresh dictionary about the new entry
    update_entr_dict(new_pd, :pd)

    begin
      new_pks = Pkgd.create!(new_pd)
    rescue Moped::Errors::OperationFailure => e
      json_return 200, 'Duplicated Package ID', component, operation, time_req_begin if e.message.include? 'E11000'
    end
    logger.cust_debug(component: component, operation: operation, message: "PD #{new_pks}")
    logger.cust_info(status: 200, start_stop:'STOP', component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

    response = ''
    case request.content_type
      when 'application/json'
        response = new_pks.to_json
      when 'application/x-yaml'
        response = json_to_yaml(new_pks.to_json)
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method update_package_id
  # @overload put '/catalogues/packages/:id/?'
  #	Update a Package in JSON or YAML format
  ## Catalogue - UPDATE
  put '/packages/:id/?' do

    # Logger details
    operation = "PUT /v2/packages/#{params[:id]}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    unless params[:id].nil?
      logger.cust_info(start_stop:'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

      # Transform 'string' params Hash into keys
      keyed_params = keyed_hash(params)

      # Check for special case (:status param == <new_status>)
      if keyed_params.key?(:status)
        # Do update of Descriptor status -> update_ns_status
        logger.cust_debug(component: component, operation: operation, message: "PUT /v2/packages/#{query_string}")


        # Validate Package
        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          pks = Pkgd.find_by('_id' => params[:id])
          logger.cust_debug(component: component, operation: operation, message: 'Package is found')
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This PD does not exists', component, operation, time_req_begin
        end

        # Validate new status
        valid_status = %w(active inactive delete)
        if valid_status.include? keyed_params[:status]
          # Update to new status
          begin
            pks.update_attributes(status: keyed_params[:status])
          rescue Moped::Errors::OperationFailure => e
            json_error 400, 'Operation failed', component, operation, time_req_begin
          end
        else
          json_error 400, "Invalid new status #{keyed_params[:status]}", component, operation, time_req_begin
        end

        json_return 200, "Status updated to {#{query_string}}", component, operation, time_req_begin

        # Check for special case (:sonp_uuid param == <uuid>)
      elsif keyed_params.key?(:sonp_uuid)
        # Do update of Package meta-data to include son-package uuid
        logger.cust_debug(component: component, operation: operation, message: "PUT /v2/packages/#{query_string}")

        # Validate Package
        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          pks = Pkgd.find_by('_id' => params[:id])
          logger.cust_debug(component: component, operation: operation, message: 'Package is found')
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'This PD does not exists', component, operation, time_req_begin
        end

        # Validate son-package uuid
        begin
          puts 'Searching ' + params[:sonp_uuid].to_s
          sonp = FileContainer.find_by('_id' => params[:sonp_uuid])
          p 'Filename: ', sonp['package_name']
          logger.cust_debug(component: component, operation: operation, message: 'son-package is found')
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, 'Submitted son-package UUID not exists', component, operation, time_req_begin
        end

        # Add new son-package uuid field
        begin
          pks.update_attributes(son_package_uuid: keyed_params[:sonp_uuid])
        rescue Moped::Errors::OperationFailure => e
          json_error 400, 'Operation failed', component, operation, time_req_begin
        end

        logger.cust_debug(component: component, operation: operation, message: "PUT /v2/packages/#{query_string}")
        json_return 200, "PD updated with son-package uuid: #{keyed_params[:sonp_uuid]}", component, operation, time_req_begin

      else
        # Compatibility support for YAML content-type
        case request.content_type
          when 'application/x-yaml'
            # Validate YAML format
            # When updating a PD, the json object sent to API must contain just data inside
            # of the pd, without the json field pd: before
            pks, errors = parse_yaml(request.body.read)
            json_error 400, errors.to_json , component, operation, time_req_begin if errors

            # Translate from YAML format to JSON format
            new_ns_json = yaml_to_json(pks)

            # Validate JSON format
            new_pks, errors = parse_json(new_ns_json)
            json_error 400, errors.to_json , component, operation, time_req_begin if errors

          else
            # Compatibility support for JSON content-type
            # Parses and validates JSON format
            new_pks, errors = parse_json(request.body.read)
            json_error 400, errors.to_json , component, operation, time_req_begin if errors
        end

        # Validate Package
        # Check if mandatory fields Vendor, Name, Version are included
        json_error 400, 'Package Vendor not found', component, operation, time_req_begin unless new_pks.has_key?('vendor')
        json_error 400, 'Package Name not found', component, operation, time_req_begin unless new_pks.has_key?('name')
        json_error 400, 'Package Version not found', component, operation, time_req_begin unless new_pks.has_key?('version')

        # Retrieve stored version
        begin
          puts 'Searching ' + params[:id].to_s
          pks = Pkgd.find_by('_id' => params[:id])
          logger.cust_debug(component: component, operation: operation, message: 'Package is found')
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The PD ID #{params[:id]} does not exist", component, operation, time_req_begin
        end

        # Check if Package already exists in the catalogue by name, vendor and version
        begin
          pks = Pkgd.find_by('pd.name' => new_pks['name'], 'pd.vendor' => new_pks['vendor'],
                                  'pd.version' => new_pks['version'])
          json_return 200, 'Duplicated Package Name, Vendor and Version', component, operation, time_req_begin
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
        new_pd = {}
        new_pd['_id'] = SecureRandom.uuid # Unique UUIDs per PD entries
        new_pd['pd'] = new_pks
        new_pd['status'] = 'active'
        new_pd['signature'] = nil
        new_pd['md5'] = checksum new_pks.to_s
        new_pd['username'] = username

        # First, Refresh dictionary about the new entry
        update_entr_dict(new_pd, :pd)

        begin
          new_pks = Pkgd.create!(new_pd)
        rescue Moped::Errors::OperationFailure => e
          json_return 200, 'Duplicated Package ID', component, operation, time_req_begin if e.message.include? 'E11000'
        end

        logger.cust_debug(component: component, operation: operation, message: "PD #{new_pks}")
        logger.cust_info(status: 200, start_stop:'STOP', component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

        response = ''
        case request.content_type
          when 'application/json'
            response = new_pks.to_json
          when 'application/x-yaml'
            response = json_to_yaml(new_pks.to_json)
          else
            halt 415
        end
        halt 200, {'Content-type' => request.content_type}, response
      end
    end
    logger.cust_debug(component: component, operation: operation, message: 'No PD ID specified')
    json_error 400, 'No PD ID specified', component, operation, time_req_begin
  end

  # @method status_package
  # @overload put '/catalogues/packages/:id/status'
  #	Update a Package status in JSON or YAML format
  ## Catalogue - UPDATE
  put '/packages/:id/status' do
    # Return if content-type is invalid
    halt 415 unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')
    case request.content_type
    when 'application/x-yaml'
      # Validate YAML format
      # When updating a PD, the json object sent to API must contain just data inside
      # of the pd, without the json field pd: before
      status_info, errors = prake ci:allarse_yaml(request.body.read)
      halt 400, errors.to_json if errors
    else
      # Compatibility support for JSON content-type
      # Parses and validates JSON format
      status_info, errors = parse_json(request.body.read)
      halt 400, errors.to_json if errors
    end
    if status_info['status'].nil?
      halt 400, JSON.generate(error: 'Status not specified')
    end
    unless status_info['status'].upcase.in?(['ACTIVE', 'INACTIVE'])
      halt 400, JSON.generate(error: 'Status should be active/inactive')
    end
    begin
      pks = Pkgd.find_by('id' => params[:id])
    rescue Mongoid::Errors::DocumentNotFound => e
      json_error 404, "The PD with id #{params[:id]} does not exist"
    end
    if status_info['status'].casecmp('INACTIVE') == 0
      logger.info "Setting pd #{params[:id]} status to inactive"
      # intelligent_disable(pks)
      pks.update('status' => 'inactive')
    else
      logger.info "Setting pd #{params[:id]} status to active"
      # intelligent_enable_all(pks)
      pks.update('status' => 'active')
    end
    logger.debug "Catalogue: leaving PUT /v2/packages/#{params[:id]}/status with 'No PD ID specified'"
    json_error 400, 'No PD ID specified'
  end

  # @method delete_pd_package_group_name_version
  # @overload delete '/catalogues/packages/vendor/:package_group/name/:package_name/version/:package_version'
  #	Delete a PD by group, name and version
  delete '/packages/?' do
    logger.info "Catalogue: entered DELETE /v2/packages?#{query_string}"

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)
    # puts 'keyed_params', keyed_params

    unless keyed_params[:vendor].nil? && keyed_params[:name].nil? && keyed_params[:version].nil?
      begin
        pks = Pkgd.find_by('pd.vendor' => keyed_params[:vendor], 'pd.name' => keyed_params[:name],
                                'pd.version' => keyed_params[:version])
        puts 'Package is found'
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The PD Vendor #{keyed_params[:vendor]}, Name #{keyed_params[:name]}, Version #{keyed_params[:version]} does not exist"
      end
      # Delete entry in dict mapping
      del_ent_dict(pks, :pd)
      intelligent_delete(pks)

      logger.debug "Catalogue: leaving DELETE v2/packages?#{query_string}\" with PD #{pks}"
      halt 200, 'OK: PD ID Removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/packages?#{query_string} with 'No PD Vendor, Name, Version specified'"
    json_error 400, 'No PD Vendor, Name, Version specified'
  end

  # @method delete_pd_package_id
  # @overload delete '/catalogues/packages/:id/?'
  #	  Delete a PD by its ID
  #	  @param :id [Symbol] identifier for PD
  # Delete a PD by uuid
  delete '/packages/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: DELETE /v2/packages/#{params[:id]}"
      begin
        pks = Pkgd.find(params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The PD ID #{params[:id]} does not exist" unless pks
      end
      # Delete entry in dict mapping

      intelligent_delete(pks)

      logger.debug "Catalogue: leaving DELETE v2/packages?#{query_string}\" with PD #{pks}"
      halt 200, 'OK: PD ID Removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/packages/#{params[:id]} with 'No PD ID specified'"
    json_error 400, 'No PD ID specified'
  end

  delete '/packages_debug/:id/?' do
    pks = Pkgd.find(params[:id])
    pks.destroy
  end
end
