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


class CatalogueV2 < SonataCatalogue
  ### FILE API METHODS ###
  #

  # @method get_file_list
  # @overload get '/cataloges/files/?'
  #	Returns a list of files
  #	-> List many files
  get '/files/?' do

    # Logger details
    operation = "GET /v2/files?#{query_string}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop: 'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    params['page_number'] ||= DEFAULT_PAGE_NUMBER
    params['page_size'] ||= DEFAULT_PAGE_SIZE


    # Return if content-type is invalid
    json_error 415, 'Support of x-yaml and json', component, operation, time_req_begin unless (request.content_type == 'application/x-yaml' or request.content_type == 'application/json')

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)

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

    # Translate 'uuid' field to '_id'
    new_params = {}
    keyed_params.each { |k, v|
        if k == :'uuid'
          new_params.store( '_id', v)
        else
          new_params.store( k, v)
        end
    }

    # Do the query
    file_list = Files.where(new_params)
    # Set total count for results
    headers 'Record-Count' => file_list.count.to_s
    logger.cust_debug(component: component, operation: operation, message: "Files=#{file_list}")


    # Paginate results
    file_list = file_list.paginate(page_number: params[:page_number],
                                   page_size: params[:page_size])
    logger.cust_info(status: 200, start_stop: 'STOP', message: "Ended at #{Time.now.utc}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

    response = ''
    case request.content_type
      when 'application/json'
        response = file_list.to_json
      else
        response = json_to_yaml(file_list.to_json)
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method get_file_id
  # @overload get '/catalogues/files/:id/?'
  #	  Get a file
  #	  @param :id [Symbol]file ID
  # file internal database identifier
  get '/files/:id/?' do

    # Logger details
    operation = "GET /v2/files/#{params[:id]}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop: 'START', component: component, operation: operation, message: "Started at #{time_req_begin}")


    # Check headers
    case request.content_type
      when 'application/octet-stream'
        begin
          file = Files.find_by({ '_id' => params[:id] })
          logger.cust_debug(component: component, operation: operation, message: "Filename=#{file['file_name']}")
          logger.cust_debug(component: component, operation: operation, message: "Files=#{file['grid_fs_id']}")

        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The file ID #{params[:id]} does not exist", component, operation, time_req_begin unless file
        end

        grid_fs = Mongoid::GridFs
        grid_file = grid_fs.get(file['grid_fs_id'])

        # Set custom header with Filename
        headers 'Filename' => (file['file_name'].to_s)

        grid_file.data # big huge blob
        # temp = Tempfile.new("#{files['file_name'].to_s}", 'wb')
        # path_file = File.basename(temp.path)
        # grid_file.each do |chunk|
        #   temp.write(chunk) # streaming write
        # end
        # temp.close
        # # Client file recovery
        # str_name = file['file_name'].split('.')
        # str_name[0] << "_" + Time.now.to_i.to_s.delete(" ")
        # temp = File.new(str_name.join("."), 'wb')
        # temp.write(grid_file.data)
        # temp.close
        logger.cust_debug(component: component, operation: operation, message: "/files/#{params[:id]}")
        logger.cust_info(status: 200, start_stop: 'STOP', message: "Ended at #{Time.now.utc}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")

        halt 200, {'Content-type' => request.content_type}, grid_file.data

      when 'application/json'
        begin
          file = Files.find_by('_id' => params[:id])
        rescue Mongoid::Errors::DocumentNotFound => e
          json_error 404, "The file ID #{params[:id]} does not exist", component, operation, time_req_begin unless file
        end

        logger.cust_debug(component: component, operation: operation, message: "/files/#{params[:id]}")
        logger.cust_info(status: 200, start_stop: 'STOP', message: "Ended at #{Time.now.utc}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")
        halt 200, {'Content-type' => 'application/json'}, file.to_json

      else
        # Return if content-type is invalid
        json_error 415, 'Support of octet-stream and json', component, operation, time_req_begin
    end
  end


  # @method post_file
  # @overload post '/catalogues/files'
  # Post a file in binary-data
  post '/files' do

    # Logger details
    operation = "POST /v2/files?#{query_string}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop: 'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    # Return if content-type is invalid
    json_error 415, 'Support of octet-stream', component, operation, time_req_begin unless request.content_type == 'application/octet-stream'
    att = request.env['HTTP_CONTENT_DISPOSITION']

    unless att
      json_error 400, "HTTP Content-Disposition is missing", component, operation, time_req_begin
    end
    if request.env['HTTP_SIGNATURE']
      signature = request.env['HTTP_SIGNATURE']
    else
      signature = nil
    end

    #Delete key "captures" if present
    params.delete(:captures) if params.key?(:captures)

    # Transform 'string' params Hash into keys
    keyed_params = keyed_hash(params)
    filename = att.match(/filename=(\"?)(.+)\1/)[2]

    # Reads body data
    file, errors = request.body
    json_error 400, errors, component, operation, time_req_begin if errors

    if keyed_params.key?(:username)
      username = keyed_params[:username]
    else
      username = nil
    end

    # For first version of 5GTANGO avoid the intelligent reuse of files
    # begin
    #   file = Files.find_by({ 'file_name' => filename })
    #   halt 409, "Duplicated file ID => #{file['_id']}"
    # rescue Mongoid::Errors::DocumentNotFound => e
    #   # Continue
    # end
    #
    # # Check if file is already in the Catalogues by filename.
    # # If yes, abort with 409 error
    # begin
    #   file_in = Files.find_by('file_name' => filename)
    #   halt 409, "Duplicated filename File ID => #{file_in['file_name']}"
    # rescue Mongoid::Errors::DocumentNotFound => e
    #   # Continue
    # end

    # Check if file is already in the Catalogues by md5, means same content.
    # If yes, increase ++ the pkg_ref
    # begin
    #   file_in = Files.find_by('md5' => checksum(file.string))
    #   if file_in['file_name'].include? filename
    #     dict = file_in['pkg_ref']
    #     dict.each do |key|
    #       if key['file_name'] == filename
    #         key['ref'] += 1
    #         break
    #       end
    #     end
    #     file_in.set('pkg_ref' => dict)
    #   else
    #     file_in.push(file_name: filename)
    #     file_in.push(pkg_ref: {'file_name' => filename, 'ref' => 1})
    #   end
    #
    #
    file_in = Files.where('md5' => checksum(file.string))
    if file_in.size.to_i > 0
      file_same = file_in.select {|ii| ii['file_name'] == filename}
      if file_same.empty?
        file_id = SecureRandom.uuid
        Files.new.tap do |file_cur|
          file_cur._id = file_id
          file_cur.grid_fs_id = file_in.first['grid_fs_id']
          file_cur.file_name = filename
          file_cur.md5 = checksum(file.string)
          file_cur.pkg_ref = 1
          file_cur.username = username
          file_cur.signature = signature
          file_cur.save
        end
        logger.cust_debug(component: component, operation: operation, message: "id #{file_id} mapped to existing md5 #{checksum(file.string)}")
      elsif file_same.count == 1
        file_same.first.update_attributes(pkg_ref: file_same.first['pkg_ref'] + 1)
        file_id = file_same.first['_id']
        logger.cust_debug(component: component, operation: operation, message: "id #{file_id} increased pkg_ref at #{file_same.first['pkg_ref']}")
      else
        logger.cust_debug(component: component, operation: operation, message: "#{checksum(file.string)} as more than one file has same filename")

        json_error 500, "More than one file has same filename. Filenames are unique per one class metadata", component, operation, time_req_begin
      end
      logger.cust_info(status: 200, start_stop: 'STOP', message: "Ended at #{Time.now.utc}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")
      response = {"uuid" => file_id}
      halt 200, {'Content-type' => 'application/json'}, response.to_json
    end


      # file_in.update_attributes(pkg_ref: file_in['pkg_ref'] + 1)
      # response = {"uuid" => file_in['_id'], "referenced" => file_in['pkg_ref']}
      # logger.info "New uuid #{file_in['_id']}"
    #   halt 200, file_in.to_json
    #   # halt 200, {'Content-type' => 'application/json'}, response.to_json
    # rescue Mongoid::Errors::DocumentNotFound => e
    #   # Continue
    # end

    grid_fs = Mongoid::GridFs

    grid_file = grid_fs.put(file,
                            filename: filename,
                            content_type: 'application/octet-stream',
    # _id: SecureRandom.uuid,
                            )



    file_id = SecureRandom.uuid
    Files.new.tap do |file|
      file._id = file_id
      file.grid_fs_id = grid_file.id
      file.file_name = filename
      # file.file_name = [filename]
      file.md5 = grid_file.md5
      file.pkg_ref = 1
      # file.pkg_ref = [{"file_name" => filename, "ref" => 1}]
      file.username = username
      file.signature = signature
      file.save
    end
    logger.cust_debug(component: component, operation: operation, message: "Grid_file id #{grid_file.id}")
    logger.cust_info(status: 201, start_stop: 'STOP', message: "Ended at #{Time.now.utc}", component: component, operation: operation, time_elapsed: "#{Time.now.utc - time_req_begin }")
    response = {"uuid" => file_id}
    halt 201, {'Content-type' => 'application/json'}, response.to_json
  end

  # @method delete_file_id
  # @overload delete '/catalogues/files/:id/?'
  #	  Delete a file by its ID
  #	  @param :id [Symbol] file ID
  delete '/files/:id/?' do

    # Logger details
    operation = "DELETE /v2/files/#{params[:id]}"
    component = __method__.to_s
    time_req_begin = Time.now.utc

    logger.cust_info(start_stop: 'START', component: component, operation: operation, message: "Started at #{time_req_begin}")

    unless params[:id].nil?
      begin
        file = Files.find_by('_id' => params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        json_error 404, "The File ID #{params[:id]} does not exist", component, operation, time_req_begin unless file
      end
      logger.cust_debug(component: component, operation: operation, message: "File #{file}")


      if file['pkg_ref'] == 1
        # Referenced only once. Delete in this case
        file.destroy
        file_md5 = Files.where('md5' => file['md5'])
        if file_md5.size.to_i.zero?
          # Remove files from grid
          grid_fs = Mongoid::GridFs
          grid_fs.delete(file['grid_fs_id'])
          logger.cust_debug(component: component, operation: operation, message: "File #{file}")
        end
        logger.cust_debug(component: component, operation: operation, message: "File referenced also by #{file_md5}")
        json_return 200, 'File removed', component, operation, time_req_begin
      else
        # Referenced above once. Decrease counter
        file.update_attributes(pkg_ref: file['pkg_ref'] - 1)
        json_return 200, "File referenced => #{file['pkg_ref']}", component, operation, time_req_begin
      end

    end
    logger.cust_debug(component: component, operation: operation, message: "No files ID specified")
    json_error 400, 'No file ID specified', component, operation, time_req_begin
  end
end
