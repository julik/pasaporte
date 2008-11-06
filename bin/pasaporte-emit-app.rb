#! /usr/bin/env ruby
require 'rubygems'
require 'pasaporte'
require 'fileutils'
FileUtils.cp_r(Pasaporte::PATH, Dir.getcwd + '/')