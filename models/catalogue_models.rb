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

# Convert BSON ID to String
module BSON
  class ObjectId
    def to_json(*)
      to_s.to_json
    end
    def as_json(*)
      to_s.as_json
    end
  end
end

module Mongoid
  module Document
    def serializable_hash(options = nil)
      h = super(options)
      h['uuid'] = h.delete('_id') if(h.has_key?('_id'))
      h
    end
  end
end



# Sonata class for Catalogue Services
class Ns
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  # include Mongoid::Versioning
  include Mongoid::Attributes::Dynamic
  store_in collection: 'nsd'

  field :vendor, type: String
  field :name, type: String
  field :version, type: String
  field :status, type: String
  validates :vendor, :name, :version, presence: true
end

# New API v2 item structure for meta-data and descriptor data
class Nsd
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic
  store_in collection: 'nsd'

  field :nsd, type: Hash
  field :status, type: String
  field :signature, type: String
  field :username, type: String
  validates :nsd, presence: true
end

# Sonata class for Catalogue Functions
class Vnf
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic
  store_in collection: 'vnfd'

  field :vendor, type: String
  field :name, type: String
  field :version, type: String
  validates :vendor, :name, :version, presence: true
end

# New API v2 item structure for meta-data and descriptor data
class Vnfd

  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic
  store_in collection: 'vnfd'

  field :vnfd
  field :status
  field :signature
  field :username

  validates :vnfd, presence: true
end

# Sonata class for Catalogue Packages
class Package
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic
  store_in collection: 'pd'

  field :vendor, type: String
  field :name, type: String
  field :version, type: String
  validates :vendor, :name, :version, presence: true
end

# New API v2 item structure for meta-data and descriptor data
class Pkgd
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic
  store_in collection: 'pd'

  field :pd, type: Hash
  field :status, type: String
  field :signature, type: String
  field :username, type: String
  validates :pd, presence: true
end

# Class model for binary data storage on database
# require 'mongoid/grid_fs'
# Sonata API v2 class for Catalogue son-packages
class FileContainer
  require 'mongoid/grid_fs'

  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic
  store_in collection: 'file_containers'

  field :grid_fs_id, type: String
  field :grid_fs_name, type: String
  # field :vendor, type: String
  # field :name, type: String
  # field :version, type: String
  field :signature, type: String
  field :md5, type: String
  field :username, type: String
end

# Sonata class for Catalogue Element Dependencies
class Dependencies_mapping
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic
  store_in collection: 'mapping_db'

  field :son_package_uuid, type: String
  field :pd, type: Hash
  field :nsds, type: Array
  field :vnfds, type: Array
  field :deps, type: Array
  field :status, type: String
  validates :son_package_uuid, :pd, :nsds, :vnfds, :status, :presence => true
end


# Class Slad for service level agreement descriptors
class Slad
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic
  store_in collection: 'slad'

  field :slad, type: Hash
  field :signature, type: String
  field :username, type: String
  validates :slad, presence: true
end

# Class tests for test descriptors
class Testd
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic
  store_in collection: 'testd'

  field :testd, type: Hash
  field :signature, type: String
  field :username, type: String
  validates :testd, presence: true
end

# Class Nst for Network Slice Templates
class Nstd
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic
  store_in collection: 'nstd'

  field :nstd, type: Hash
  field :signature, type: String
  field :username, type: String
  validates :nstd, presence: true
end

# Class Nst for Network Slice Templates
class Pld
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic
  store_in collection: 'pld'

  field :pld, type: Hash
  field :signature, type: String
  field :username, type: String
  validates :pld, presence: true
end

# Class Dict for Inverted Index
class Dict
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Pagination
  include Mongoid::Attributes::Dynamic

  store_in collection: 'dictionary'
end