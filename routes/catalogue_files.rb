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
    params['page_number'] ||= DEFAULT_PAGE_NUMBER
    params['page_size'] ||= DEFAULT_PAGE_SIZE

    logger.info "Catalogue: entered GET /v2/files?#{query_string}"

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
    logger.info "Catalogue: leaving GET /v2/files?#{query_string} with #{file_list}"

    # Paginate results
    file_list = file_list.paginate(page_number: params[:page_number],
                                   page_size: params[:page_size])

    response = ''
    case request.content_type
      when 'application/json'
        response = file_list.to_json
      when 'application/x-yaml'
        response = json_to_yaml(file_list.to_json)
      else
        halt 415
    end
    halt 200, {'Content-type' => request.content_type}, response
  end

  # @method get_file_id
  # @overload get '/catalogues/files/:id/?'
  #	  Get a file
  #	  @param :id [Symbol]file ID
  # file internal database identifier
  get '/files/:id/?' do
    # Dir.chdir(File.dirname(__FILE__))
    logger.debug "Catalogue: entered GET /v2/files/#{params[:id]}"

    # Check headers
    case request.content_type
      when 'application/octet-stream'
        begin
          file = Files.find_by({ '_id' => params[:id] })
          p 'Filename: ', file['file_name']
          p 'grid_fs_id: ', file['grid_fs_id']
        rescue Mongoid::Errors::DocumentNotFound => e
          logger.error e
          halt 404
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

        logger.debug "Catalogue: leaving GET /files/#{params[:id]}"
        halt 200, {'Content-type' => request.content_type}, grid_file.data

      when 'application/json'
        begin
          file = Files.find_by('_id' => params[:id])
        rescue Mongoid::Errors::DocumentNotFound => e
          logger.error e
          json_error 404, "The file ID #{params[:id]} does not exist" unless file
        end

        logger.debug "Catalogue: leaving GET /v2/files/#{params[:id]}"
        halt 200, {'Content-type' => 'application/json'}, file.to_json

      else
        halt 415
    end
  end


  # @method post_file
  # @overload post '/catalogues/files'
  # Post a file in binary-data
  post '/files' do
    logger.debug "Catalogue: entered POST /v2/files?#{query_string}"
    # Return if content-type is invalid
    halt 415 unless request.content_type == 'application/octet-stream'

    att = request.env['HTTP_CONTENT_DISPOSITION']

    unless att
      error = "HTTP Content-Disposition is missing"
      halt 400, error.to_json
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
    halt 400, errors.to_json if errors

    # For first version of 5GTANGO avoid the intelligent reuse of files
    # begin
    #   file = Files.find_by({ 'file_name' => filename })
    #   halt 409, "Duplicated file ID => #{file['_id']}"
    # rescue Mongoid::Errors::DocumentNotFound => e
    #   # Continue
    # end

    grid_fs = Mongoid::GridFs

    grid_file = grid_fs.put(file,
                            filename: filename,
                            content_type: 'application/octet-stream',
    # _id: SecureRandom.uuid,
                            )

    if keyed_params.key?(:username)
      username = keyed_params[:username]
    else
      username = nil
    end

    file_id = SecureRandom.uuid
    Files.new.tap do |file|
      file._id = file_id
      file.grid_fs_id = grid_file.id
      file.file_name = filename
      file.md5 = grid_file.md5
      file.username = username
      file.signature = signature
      file.save
    end
    logger.debug "Catalogue: leaving POST /v2/files/ with #{grid_file.id}"
    response = {"uuid" => file_id}

    halt 201, {'Content-type' => 'application/json'}, response.to_json
  end

  # @method delete_file_id
  # @overload delete '/catalogues/files/:id/?'
  #	  Delete a file by its ID
  #	  @param :id [Symbol] file ID
  delete '/files/:id/?' do
    unless params[:id].nil?
      logger.debug "Catalogue: entered DELETE /v2/files/#{params[:id]}"
      begin
        file = Files.find_by('_id' => params[:id])
      rescue Mongoid::Errors::DocumentNotFound => e
        logger.error e
        json_error 404, "The file ID #{params[:id]} does not exist" unless file
      end

      # Remove files from grid
      grid_fs = Mongoid::GridFs
      grid_fs.delete(file['grid_fs_id'])
      file.destroy

      logger.debug "Catalogue: leaving DELETE /v2/files/#{params[:id]}\" with file #{file}"
      halt 200, 'OK: file removed'
    end
    logger.debug "Catalogue: leaving DELETE /v2/files/#{params[:id]} with 'No files ID specified'"
    json_error 400, 'No file ID specified'
  end
end
