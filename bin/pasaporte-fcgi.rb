#! /usr/bin/env ruby
require 'rubygems'
require 'camping'
require 'camping/fastcgi'
require File.dirname(__FILE__) + '/../lib/pasaporte'

Camping::Models::Base.establish_connection(
        :adapter => 'sqlite3',
        :database => ENV['HOME'] + '/pasaporte.sqlitedb'
)

Pasaporte.create
Pasaporte::LOGGER = Logger.new(ENV['HOME'] + "/pasaporte.log")

ENV.keys.grep(/^PASAPORTE_/).each do | envar |
  Pasaporte.const_set(envar.gsub(/^PASAPORTE_/, ''), ENV[envar])
end

serv = Camping::FastCGI.new
serv.mount('/', Pasaporte)
serv.start