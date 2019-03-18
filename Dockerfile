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

FROM ruby:2.4.3-slim-stretch
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential libcurl3 libcurl3-gnutls libcurl4-openssl-dev && \
          apt-get clean && \
          apt-get autoremove && \
	  rm -rf /var/lib/apt/lists/*
RUN mkdir -p /app
COPY Gemfile /app/
WORKDIR /app
RUN bundle install

ENV tngVnvDsmUrl = http://tng-vnv-dsm:4010/api
FROM ruby:2.4.3-slim-stretch
COPY --from=0 /usr/local/bundle /usr/local/bundle
RUN apt-get update && \
    apt-get install -y --no-install-recommends libcurl3 libcurl3-gnutls libcurl4-openssl-dev && \
          apt-get clean && \
          apt-get autoremove && \
          rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN rake yard
ENV PORT 4011
EXPOSE 4011
CMD ["rake", "start"]
