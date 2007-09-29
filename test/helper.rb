require File.dirname(__FILE__) + '/mosquito'
require File.dirname(__FILE__) + '/../app/pasaporte'

require 'flexmock'
require 'flexmock/test_unit'

# for assert_select and friends
require 'action_pack'
require 'action_controller/assertions'

class Pasaporte::Controllers::ServerError
  def get(*all)
    raise all.pop
  end
end

Test::Unit::TestCase.fixture_path = File.dirname(__FILE__) + "/fixtures/"
ActiveRecord::Base.logger = Logger.new("/dev/null") # SAILENS!

Pasaporte::LOGGER.level = Logger::INFO

def mock_auth(log, pass, dom)
  logins = %w(monsieur-hulot julian jamesbrown)
  passes = logins.map(&:reverse)
  logins.index(log) && (logins.index(log) == passes.index(pass))
end

silence_warnings do
  Pasaporte.const_set(:LOGGER, Logger.new(File.dirname(__FILE__) + "/test.log"))
  Pasaporte.const_set(:AUTH, lambda{|l, p, d| mock_auth(l, p, d) })
end


ActiveRecord::Migration.suppress_messages { Pasaporte.create }
include Pasaporte::Models

class Pasaporte::WebTest < Camping::WebTest
  def setup; super; @class_name_abbr = 'Pasaporte'; end
  attr_reader :html_document
  def send_request(*a)
    returning(super(*a)) do
      @html_document = HTML::Document.new(@response.body.to_s) unless @response.headers["Location"]
    end
  end
end