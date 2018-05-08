
[![Build Status](http://jenkins.sonata-nfv.eu/buildStatus/icon?job=tng-cat)](http://jenkins.sonata-nfv.eu/job/tng-cat)  
  
# TNG Catalogue  
This repository contains the development for the [5GTANGO](https://5gtango.eu/) 's Service Platform Catalogue. It holds the API implementation for the Service Platform Catalogue component.  
The Catalogue now integrates the SDK [tng-catalogue](https://github.com/sonata-nfv/tng-cat) in the Service Platform. It is closely related to the [tng-schema](https://github.com/sonata-nfv/tng-schema) repository that holds the schema for the various descriptors.  
  
## Development  
To contribute to the development of the 5GTANGO Catalogue, you may use the very same development workflow as for any other 5GTANGOO Github project. That is, you have to fork the repository and create pull requests.  
  
### Dependencies  
It is recommended to use Ubuntu 16.04.4 LTS (Trusty Tahr).  
  
This code has been run on Ruby 2.3.  
  
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
  
The Catalogue's API allows the use of CRUD operations to send, retrieve, update and delete descriptors and tng files. The available descriptors include Network Service (NSD), Virtualized Network Function (VNFD), Package (PD), Service Level Agreements (SLAD), Test (TESTD), Network Slice Templates (NST) and Policy (PLD) Descriptors.
The Catalogue also support storage for 5GTANGO packages (tng-packages), the binary files that contain the descriptors.  
For testing the Catalogues, you can use 'curl' tool to send a request descriptors to the API. It is required to set the HTTP header 'Content-type' field to 'application/json' or 'application/x-yaml' according to your desired format.  
  
The Catalogues' API now supports API versioning. New API v2 has been introduced in release v2.0 which implements some structure changes in the descriptors.  
The API v1 is deprecated and is no longer supported by the 5GTANGO Service Platform. It is recommended to use v2 only in a MongoDB database.  
  
Below, the CRUD methods of the Catalogues are presented. Note that the attached files should be in the current directory. In any other occasion, the examples, used below to reference the operations, are in the directory "samples/".  

  | Action | HTTP Method | Endpoint |  
| -------------------------- | -------- | --------------------------------------- |  
| List all the available descriptors | `GET` | `curl -H <Content-Type> http://localhost:4011/api/catalogues/v2/{collection}` |  
| List all descriptors matching a specific filter(s) | `GET` | `curl -H <Content-Type> http://localhost:4011/api/catalogues/v2/{collection}?{attributeName}={value}` |  
| List only the last version for all descriptors | `GET` | `curl -H <Content-Type> http://localhost:4011/api/catalogues/v2/{collection}?version=last` |  
| List a descriptor using the UUID | `GET` | `curl -H <Content-Type> http://localhost:4011/api/catalogues/v2/{collection}/{id}` |  
| Store a descriptor in the Catalogue | `POST` | `curl -X POST --data-binary @nsd_example.yml -H <Content-Type> http://localhost:4011/api/catalogues/v2/{collection} ` |  
| Update a descriptor, since an older version is hosted | `PUT` | `curl -X PUT --data-binary @nsd_example.yml -H <Content-Type> http://localhost:4011/api/catalogues/v2/{collection}` | 
| Delete a descriptor using the UUID | `DELETE` | `curl -X DELETE http://localhost:4011/api/catalogues/v2/{collection}/{id}  ` |

where `{collection}` denotes the type of collection and is one of the `network-services`, `vnfs`, `packages`, `slas/template-descriptors`, `tests`, `nsts`, `policies` and `<Content-Type>` header can be `"Content-Type: application/x-yaml"` or `"Content-Type: application/json"`. Examples can be found in the relative [wiki page](https://github.com/sonata-nfv/tng-cat/wiki/Examples)
  
The API for 5GTANGO packages (tgo-package) and arbitrary files works very similar to the API for the descriptors.  
   | Action | HTTP Method | Endpoint |  
| -------------------------- | -------- | --------------------------------------- |  
| List the metadata of all stored packages/files | `GET` | `curl -H <Content-Type> http://localhost:4011/api/catalogues/v2/{collection}` (see Note 1)|  
| List metadata of a specific packages/files| `GET` | `curl -H <Content-Type> http://localhost:4011/api/catalogues/v2/{collection}/{id}` (see Note 2) |  
| Store a package/file in the Catalogue | `POST` | `curl -X POST -H <Content-Type> -H "Content-Disposition: attachment; filename=<filename>" --data-binary @<filename>  http://localhost:4011/api/catalogues/v2/{collection}` (see Note 3)|  
| Delete a package/file using its UUID | `DELETE` | `curl -X DELETE http://localhost:4011/api/catalogues/v2/{collection}/{id}    ` |

where `{collection}` is one of the `tgo-packages`,`files` and is strictly correlated with the `<Content-Type>` on the grounds that is `"Content-Type: application/zip"`for tgo-packages and `"Content-Type: application/octet-stream"` for files.

__Note 1__: Since the metadata are returned, the `<Content-Type>`header can be defined as `"Content-Type: application/x-yaml"` or `"Content-Type: application/json"`.

__Note 2__: `<Content-Type>` header defines the functionality of this endpoint. By setting`"Content-Type: application/x-yaml"` or `"Content-Type: application/json"`, the metadata of the specific tgo-package are listed. With `"Content-Type: application/zip"`, the raw binary data of the tgo-package are returned. Correspondingly, with`"Content-Type: application/octet-stream"`, the raw binary data of the arbitrary file are returned.

__Note 3__: `<Content-Type>` header can be defined as`"Content-Type: application/zip"`for tgo-packages and `"Content-Type: application/octet-stream"` for files.

Examples can be found in the relative [wiki page](https://github.com/sonata-nfv/tng-cat/wiki/Examples)

In order to associate the package with its content, it needs the provision of  a file including the {name, vendor, version} trios of the Package, VNF and NS descriptors along with the {file_uuid, file_name} pair of every arbitrary file in the package.  
The validity of the mapping file is done by examining the existence of every entity mentioned inside. In order to send this type of file:  
```  
curl -X POST -H "Content-Type: application/json" --data-binary @package_mapping_file.json  http://localhost:4011/api/catalogues/v2/tgo-packages/mappings  
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
  
* Panagiotis Stavrianos (panstav1)  
* Felipe Vicens (felipevicens)  
  
## Feedback-Channel  
  
Please use the GitHub issues and the SONATA development mailing list sonata-dev@lists.atosresearch.eu for feedback.
