[![Build Status](http://jenkins.sonata-nfv.eu/buildStatus/icon?job=son-catalogue-repos)](http://jenkins.sonata-nfv.eu/job/son-catalogue-repos)

# SON Catalogue
This repository contains the development for the [5GTANGO](https://5gtango.eu/) 's Service Platform Catalogue. It holds the API implementation for the Service Platform Catalogue component.
The Catalogue now integrates the SDK [tng-catalogue](https://github.com/sonata-nfv/tng-cat) in the Service Platform. It is closely related to the [tng-schema](https://github.com/sonata-nfv/tng-schema) repository that holds the schema for the various descriptors, such as the VNFD and the NSD.

## Development
To contribute to the development of the 5GTANGO Catalogue, you may use the very same development workflow as for any other 5GTANGOO Github project. That is, you have to fork the repository and create pull requests.

### Dependencies
It is recommended to use Ubuntu 14.04.4 LTS (Trusty Tahr).

This code has been run on Ruby 2.1.

A connection to a MongoDB is required, this code has been run using MongoDB version 3.2.1.

Root folder provides a script "installation_mongodb.sh" to install and set up a local MongoDB, or you can use mongoexpress to manage the remote mongo databases.

Ruby gems used (for more details see Gemfile):
* [Sinatra](http://www.sinatrarb.com/) - Ruby framework
* [puma](http://puma.io/) - Web server
* [json](https://github.com/flori/json) - JSON specification
* [sinatra-contrib](https://github.com/sinatra/sinatra-contrib) - Sinatra extensions
* [rake](http://rake.rubyforge.org/) - Ruby build program with capabilities similar to make
* [JSON-schema](https://github.com/ruby-json-schema/json-schema) - JSON schema validator
* [jwt](https://github.com/jwt/ruby-jwt) - Json Web Token lib
* [curb](https://github.com/taf2/curb) - HTTP and REST client
* [Yard](https://github.com/lsegal/yard) - Documentation generator tool
* [mongoid-grid_fs](https://github.com/mongoid/mongoid-grid_fs) - Implementation of the MongoDB GridFS specification

### Contributing
You may contribute to the editor similar to other 5GTANGO (sub-) projects, i.e. by creating pull requests.

## Installation

After cloning the source code from the repository, you can run Catalogue with the next command:

```sh
bundle install
```
Which will install all the gems needed to run, or if you have docker and docker-compose installed, you can run

```sh
docker-compose up
```

## Usage
The following shows how to start the API server for the Catalogues-Repositories:

```sh
rake start
```

or you can use docker-compose

```sh
docker-compose up
```

The Catalogue's API allows the use of CRUD operations to send, retrieve, update and delete descriptors and tng files.
The available descriptors include services (NSD), functions (VNFD) and packages (PD) descriptors.
The Catalogue also support storage for 5GTANGO packages (tng-packages), the binary files that contain the descriptors.
For testing the Catalogues, you can use 'curl' tool to send a request descriptors to the API. It is required to set the HTTP header 'Content-type' field to 'application/json' or 'application/x-yaml' according to your desired format.

The Catalogues' API now supports API versioning. New API v2 has been introduced in release v2.0 which implements some structure changes in the descriptors.
The API v1 is deprecated and is no longer supported by the 5GTANGO Service Platform. It is recommended to use v2 only in a MongoDB database.

Method GET:

To receive all descriptors you can use

```sh
curl http://localhost:4011/catalogues/api/v2/network-services
```
```sh
curl http://localhost:4011/catalogues/api/v2/vnfs
```
```sh
curl http://localhost:4011/catalogues/api/v2/packages
```

To receive a descriptor by its ID:

```sh
curl http://localhost:4011/catalogues/api/v2/network-services/9f18bc1b-b18d-483b-88da-a600e9255016
```
```sh
curl http://localhost:4011/catalogues/api/v2/vnfs/9f18bc1b-b18d-483b-88da-a600e9255017
```
```sh
curl http://localhost:4011/catalogues/api/v2/packages/9f18bc1b-b18d-483b-88da-a600e9255018
```

Method POST:

To send a descriptor

```sh
curl -X POST --data-binary @nsd_sample.yaml -H "Content-type:application/x-yaml" http://localhost:4011/catalogues/api/v2/network-services
```
```sh
curl -X POST --data-binary @vnfd_sample.yaml -H "Content-type:application/x-yaml" http://localhost:4011/catalogues/api/v2/vnfs
```
```sh
curl -X POST --data-binary @pd_sample.yaml -H "Content-type:application/x-yaml" http://localhost:4011/catalogues/api/v2/packages
```

Method PUT:

To update a descriptor is similar to the POST method, but it is required that a older version of the descriptor is stored in the Catalogues

```sh
curl -X POST --data-binary @nsd_sample.yaml -H "Content-type:application/x-yaml" http://localhost:4011/catalogues/api/v2/network-services
```
```sh
curl -X POST --data-binary @vnfd_sample.yaml -H "Content-type:application/x-yaml" http://localhost:4011/catalogues/api/v2/vnfs
```
```sh
curl -X POST --data-binary @pd_sample.yaml -H "Content-type:application/x-yaml" http://localhost:4011/catalogues/api/v2/packages
```

Method DELETE:

To remove a descriptor by its ID

```sh
curl -X DELETE http://localhost:4011/catalogues/network-services/api/v2/9f18bc1b-b18d-483b-88da-a600e9255016
```
```sh
curl -X DELETE http://localhost:4011/catalogues/vnfs/api/v2/9f18bc1b-b18d-483b-88da-a600e9255017
```
```sh
curl -X DELETE http://localhost:4011/catalogues/packages/api/v2/9f18bc1b-b18d-483b-88da-a600e9255018
```

The API for 5GTANGO packages (tng-package) files works very similar to the API for the descriptors.

Method GET:

To receive a list of stored packages

```sh
curl http://localhost:4011/catalogues/api/v2/tng-packages
```

To receive a package file

```sh
curl http://localhost:4011/catalogues/api/v2/tng-packages/9f18bc1b-b18d-483b-88da-a600e9255000
```
Method POST:

To send a package file

HTTP header 'Content-Type' must be set to 'application/zip'

HTTP header 'Content-Disposition' must be set to 'attachment; filename=```name_of_the_package```'

```sh
curl -X POST -H "Content-Type: application/zip" -H "Content-Disposition: attachment; filename=sonata_example.tng" -F "@sonata-demo.tng" "http://0.0.0.0:4011/catalogues/api/v2/tng-packages"
```

Method DELETE:

To remove a package file by its ID

```sh
curl -X DELETE http://localhost:4011/catalogues/api/v2/tng-packages/9f18bc1b-b18d-483b-88da-a600e9255000
```

### Pushing 'tango-demo' files to Catalogue

The Rakefile in root folder includes an specific task to fill the Catalogue with descriptor sample files from
tango-demo package. This is specially useful when starting an empty Catalogue. It can be run with a rake task:

```sh
rake init:load_samples[<server>]

Where <server> allows two options: 'development' or sh'integration' server deployment
```

An example of usage:

```sh
rake init:load_samples[integration]
```


### API Documentation
Currently, the API is documented with yardoc and can be built with a rake task:

```sh
rake yard
```

From here you can use the yard server to browse the docs from the source root:

```sh
yard server
```

And they can be viewed from http://localhost:8808/
or you can use docker-compose and view from http://localhost:8808/

## License

The 5GTANGO Catalogue is published under Apache 2.0 license. Please see the LICENSE file for more details.

## Useful Links

To support working and testing with the tng-catalogue database it is optional to use next tools:

* [Robomongo](https://robomongo.org/download) - Robomongo 0.9.0-RC4

* [POSTMAN](https://www.getpostman.com/) - Chrome Plugin for HTTP communication

---
#### Lead Developers

The following lead developers are responsible for this repository and have admin rights. They can, for example, merge pull requests.

* Felipe Vicens (felipevicens)
* Daniel Guija (dang03)
* Santiago Rodriguez (srodriguezOPT)

#### Feedback-Channel

Please use the GitHub issues and the SONATA development mailing list sonata-dev@lists.atosresearch.eu for feedback.
