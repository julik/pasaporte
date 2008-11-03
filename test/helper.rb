require 'rubygems'
#gem 'activesupport', '<=2.0.2'
$:.reject! { |e| e.include? 'TextMate' }

require File.dirname(__FILE__) + '/../lib/pasaporte'
require File.dirname(__FILE__) + '/mosquito'

require 'flexmock'
require 'flexmock/test_unit'

# for assert_select and friends
require 'action_controller'
require 'action_controller/assertions'

class Pasaporte::Controllers::ServerError
  def get(*all)
    raise all.pop
  end
end

Test::Unit::TestCase.fixture_path = File.dirname(__FILE__) + "/fixtures/"
ActiveRecord::Base.logger = Logger.new("/dev/null") # SAILENS!
Pasaporte::LOGGER.level = Logger::ERROR

def mock_auth(log, pass, dom)
  logins = %w(monsieur-hulot julian jamesbrown)
  passes = logins.map(&:reverse)
  logins.index(log) && (logins.index(log) == passes.index(pass))
end

test_logger = Logger.new(File.dirname(__FILE__) + "/test.log")

silence_warnings do
  Pasaporte.const_set(:LOGGER, test_logger)
  Pasaporte.const_set(:AUTH, lambda{|l, p, d| mock_auth(l, p, d) })
end
ActiveRecord::Base.logger = test_logger

ActiveRecord::Migration.suppress_messages { Pasaporte.create }

include Pasaporte::Models

class Pasaporte::WebTest < Camping::WebTest
  if respond_to?(:set_fixture_class)
    set_fixture_class :pasaporte_approvals => Pasaporte::Models::Approval,
                      :pasaporte_profiles => Pasaporte::Models::Profile,
                      :pasaporte_throttles => Pasaporte::Models::Throttle
  end
  
  def setup
    super; @class_name_abbr = 'Pasaporte'
  end
  
  def prelogin(login)
    flexmock(Pasaporte::AUTH).
      should_receive(:call).with(login, "schweet", @request.domain).once.and_return(true)
    post "/#{login}/signon", :pass => "schweet"
  end
  
  attr_reader :html_document
  def send_request(*a)
    returning(super(*a)) do
      @html_document = HTML::Document.new(@response.body.to_s) unless @response.headers["Location"]
    end
  end
end