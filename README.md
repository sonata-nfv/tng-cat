
[![Build Status](https://jenkins.sonata-nfv.eu/buildStatus/icon?job=tng-cat/master)](https://jenkins.sonata-nfv.eu/job/tng-cat/master)  [![Join the chat at https://gitter.im/sonata-nfv/5gtango-sp](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/sonata-nfv/5gtango-sp)
<p align="center"><img src="https://github.com/sonata-nfv/tng-api-gtw/wiki/images/sonata-5gtango-logo-500px.png" /></p>
  
# 5GTANGO Catalogue 
 
This repository contains the development for the [5GTANGO](https://5gtango.eu/)'s Service Platform Catalogue and holds the API implementation for the Service Platform Catalogue component. The 5GTANGO catalogue provides management and storage of all descriptors, 5GTANGO packages and files produced from the several 5GTANGO components. The  stored  descriptors  are  required  for  the  selection,  development  and instantiation of network services as well as for data analysis. This repository comprises a basic component for the functionality of the following components:

* [tng-sdk-package](https://github.com/sonata-nfv/tng-sdk-package) -  The 5GTANGO SDK tool to create and unpack 5GTANGO packages.
* [tng-gtk-sp](https://github.com/sonata-nfv/tng-gtk-sp) - The 5GTANGO Gatekeeper Service Platform specific components repository.
 
Also, it is closely related to the [tng-schema](https://github.com/sonata-nfv/tng-schema) repository that holds the schema for the various descriptors.  For additional information in the context of the architecture, please check the [Introduction wiki page](https://github.com/sonata-nfv/tng-cat/wiki/Introduction) of this repository.
  
## Installation 

### Installing from code

To have it up and running from code, please do the following:

```shell
$ git clone https://github.com/sonata-nfv/tng-cat.git # Clone this repository
$ cd tng-cat # Go to the downloaded folder of tng-cat
$ bundle install # Install dependencies and appropriate gems
$ rake start #  server at http://localhost:4011
```

Thus, a server will be running on that session, on port `4011`. You can access it by using `curl`, like in:

```shell
$ curl <host name>:4011/
``` 

### Docker Container
In case of having docker and docker-compose installed, you can run  
  
```sh  
docker-compose up  
```  

## Developing/Contributing
To contribute to the development of the 5GTANGO Catalogue, you may use the very same development workflow as for any other 5GTANGOO Github project. That is, you have to fork the repository and create pull requests.

## Versioning

The most up-to-date version is v4. For the versions available, see the [releases tab of this repository](https://github.com/sonata-nfv/tng-cat/releases).


### Dependencies
In this repository, the following libraries are used (also referenced in the [`Gemfile`](https://github.com/sonata-nfv/tng-cat/blob/master/Gemfile) file) for development:

* [Puma](http://puma.io/) (`v.3.4.0`) - an application Web server;
* [Rake](http://rake.rubyforge.org/) (`v.11.2.2`) - Ruby build program with capabilities similar to make
* [Sinatra](http://www.sinatrarb.com/) (`v.2.0.1`), a web framework for implementing efficient ruby APIs;
* [Sinatra-contrib](https://github.com/sinatra/sinatra-contrib) (`v.2.0.1`) - Sinatra extensions  
* [Jwt](https://github.com/jwt/ruby-jwt) (`v.1.5.5`) - Json Web Token lib  
* [Curb](https://github.com/taf2/curb) (`v.0.9.3`) - HTTP and REST client  
* [Yard](https://github.com/lsegal/yard) (`v.0.9.12`) - Documentation generator tool
* [Json](https://github.com/flori/json) (`v.1.8`) - JSON specification  
* [JSON-schema](https://github.com/ruby-json-schema/json-schema) (`v.2.5`) - JSON schema validator  

Below, the gems are used for the MongoDB functionalities:

* [Mongoid](https://github.com/mongodb/mongoid) (`v.4.0`) - Ruby ODM framework for MongoDB
* [Mongoid-grid_fs](https://github.com/mongoid/mongoid-grid_fs) (`v.2.2`) - Implementation of the MongoDB GridFS specification

The following *gems* (libraries) are used just for tests:
* [Rack-test](https://rubygems.org/gems/rack-test/versions/0.6.3) (`v.0.6.2`), a helper testing framework for `rack`-based applications;
* [Rspec](https://rubygems.org/gems/rspec/versions/3.4.0) (`v.3.5.0`), a testing framework for ruby;
* [Rubocop](https://github.com/rubocop-hq/rubocop) (`v.0.48.0`), a library for white box tests; 
* [Rubocop-checkstyle_formatter](https://rubygems.org/gems/rubocop-checkstyle_formatter/versions/0.2.0) (`v.0.2.0`), a helper library for `rubocop`;
* [Webmock](https://rubygems.org/gems/webmock/versions/2.1.0) (`v.2.1.0`), which allows *mocking* (i.e., faking) HTTP calls;


These libraries are installed/updated in the developer's machine when running the command (see above):

```shell
$ bundle install
```

### Prerequisites
For the download of these libraries, [`rbenv`](https://github.com/rbenv/rbenv) is used as the ruby version manager, but others like [`rvm`](https://rvm.io/) may work as well.

### Setting up Dev
Developing this micro-service is straightforward with a low amount of necessary steps.

Routes within the micro-service are defined in the [`config.ru`](https://github.com/sonata-nfv/tng-cat/blob/master/config.ru) file, in the root directory. It has two sections:

* The `require` section, where all used libraries must be required 
* The `map` section, where this micro-service's routes are mapped to the controller responsible for it.


### Tests
Unit tests are defined for every endpoint provided in the `routes` folder, in the `/spec` folder. Since we use `rspec` as the test library, we configure tests in the [`spec_helper.rb`](https://github.com/sonata-nfv/tng-cat/blob/master/spec/spec_helper.rb) file, also in the `/spec` folder.
Every necessary file for the implementation of all the spec tests are provided in the [/fixtures](https://github.com/sonata-nfv/tng-cat/tree/master/spec/fixtures) and the [/samples](https://github.com/sonata-nfv/tng-cat/tree/master/samples/dependencies_mapping) folder.
These tests are executed by running the following command:
```shel
$ rake ci:all
```

### Submitting/Requesting changes
Changes to the repository can be requested using [this repository's issues](https://github.com/sonata-nfv/tng-cat/issues) and [pull requests](https://github.com/sonata-nfv/tng-cat/pulls) mechanisms.


## Usage
  
The Catalogue's API allows the use of CRUD operations to send, retrieve, update and delete descriptors and tng files. The available descriptors include Network Service (NSD), Virtualized Network Function (VNFD), Package (PD), Service Level Agreements (SLAD), Test (TESTD), Network Slice Templates (NST) and Policy (PLD) Descriptors.
The Catalogue also support storage for 5GTANGO packages (tng-packages), the binary files that contain the descriptors.  For testing the Catalogues, you can use 'curl' tool to send a request descriptors to the API. 
  
  
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

Examples can be found in the relative [wiki page](https://github.com/sonata-nfv/tng-cat/wiki/General-Description-of-Catalogues-API) and detailed information can be found in the [wiki](https://github.com/sonata-nfv/tng-cat/wiki)

  
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
  
  
## API Documentation  
Currently, the API is documented with yardoc and can be built with a rake task:  
  
```sh  
rake yard  
```  
 
From here you can use the yard server to browse the docs from the source root:  
  
```sh  
yard server  
```  
  
And they can be viewed from http://localhost:8808/ or you can use docker-compose and view from http://localhost:8808/. Also, the micro-service's API has been documented in a [swagger](https://github.com/sonata-nfv/tng-cat/blob/master/public/tng-cat-rest.json)-formated file.
  
## License  
  
The 5GTANGO Catalogue is published under Apache 2.0 license. Please see the LICENSE file for more details.  
  
## Useful Links  
  
To support working and testing with the tng-catalogue database it is optional to use next tools:  
  
* [Robomongo](https://robomongo.org/download) - Robomongo 0.9.0-RC4  
* [POSTMAN](https://www.getpostman.com/) - Chrome Plugin for HTTP communication  

---  
## Lead Developers  
  
The following lead developers are responsible for this repository and have admin rights. They can, for example, merge pull requests.  
  
* Panagiotis Stavrianos (panstav1)  
  
## Feedback-Channel  
  
* You may use the mailing list [sonata-dev-list](mailto:sonata-dev@lists.atosresearch.eu)
* Gitter room [![Gitter](https://badges.gitter.im/sonata-nfv/Lobby.svg)](https://gitter.im/sonata-nfv/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
