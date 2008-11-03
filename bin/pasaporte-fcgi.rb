#!/usr/bin/env ruby
require 'rubygems'
require 'camping'
require 'camping/fastcgi'
require File.dirname(__FILE__) + '/../app/pasaporte'

Camping::Models::Base.establish_connection(
        :adapter => 'sqlite3',
        :database => ENV['HOME'] + '/pasaporte.sqlitedb'
)

Pasaporte.create
Pasaporte::LOGGER = Logger.new(ENV['HOME'] + "/pasaporte.log")

serv = Camping::FastCGI.new
serv.mount('/', Pasaporte)
serv.start