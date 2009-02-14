$:.reject! { |e| e.include? 'TextMate' }
require File.dirname(__FILE__) + '/helper'
require 'fileutils'
require File.dirname(__FILE__) + '/testable_openid_fetcher'
require 'openid/store/memory'
require 'openid/extensions/sreg'

class TestWithPartialSSL < Pasaporte::WebTest
  # We have to open up because it's the Fecther that's going
  # to make requests
  attr_reader :request, :response
  fixtures :pasaporte_profiles

  def setup
    super
    @fetcher = TestableOpenidFetcher.new(self)
    
    OpenID.fetcher = @fetcher
    OpenID::Util.logger = Pasaporte::LOGGER
    
    @store = OpenID::Store::Memory.new
    @openid_session = {}
    init_consumer
    
    @request.domain = 'test.host'
    
    @trust_root = 'http://tativille.fr/wiki'
    @return_to = 'http://tativille.fr/wiki/signup'
    @hulot = Profile.find(1)
    silence_warnings {  Pasaporte.const_set(:PARTIAL_SSL, true) }
  end
  
  def teardown
    # Delete all the associations created during the test case
    JulikState::State.delete_all; Association.delete_all; Approval.delete_all; Throttle.delete_all
    # Delete the store
    FileUtils.rm_rf('openid-consumer-store')
    # Call super for flexmock a.o.
    silence_warnings {  Pasaporte.const_set(:PARTIAL_SSL, false) }
    super
  end
  
  def test_in_which_monsieur_hulot_is_not_logged_in_and_asked_for_login_after_setup_and_gets_bounced_to_ssl_page
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    assert_kind_of OpenID::Consumer::CheckIDRequest, req
    assert_nothing_raised { get_with_verbatim_url req.redirect_url(@trust_root, @return_to) }
    assert_response :redirect
    
    redirection = @response.headers['Location']
    assert_redirected_to '/monsieur-hulot/signon'
    follow_redirect
    
    assert_response :redirect
    assert_match /^https/, @response.headers['Location'].to_s, "Signon should redirect to itself over HTTPS"
    
    assert_not_nil @state.pending_openid, "A pending OpenID request should have been "+
      "placed in the session"
      
    # TODO: Verify that the cookie indeed gets transferred along to the SSL domain
    assert_kind_of OpenID::Server::CheckIDRequest, @state.pending_openid
  end
  
  private
    
    def init_consumer
      @consumer = OpenID::Consumer.new(@openid_session, @store)
    end
    def decode_qs(qs)
      qs.to_s.split(/\&/).inject({}) do | params, segment |
        k, v = segment.split(/\=/).map{|s| Camping.un(s)}
        params[k] = v; params
      end
    end
    def response_to_hash
      Hash[*@response.body.split(/\n/).map{|p| p.split(/\:/)}.flatten].with_indifferent_access
    end
    def redirect_path_and_params(t = nil)
      # Camping conveniently places a URI object in the location header
      uri = (t ? URI.parse(t) : @response.headers["Location"])
      [uri.path, decode_qs(uri.query)]
    end
    
    def redirect_url_path_and_params(t = nil)
      # Camping conveniently places a URI object in the location header
      uri = (t ? URI.parse(t) : @response.headers["Location"])
      uri_with_scheme, qry = uri.to_s.split(/\?/)
      
      [uri_with_scheme, uri.path, decode_qs(qry)]
    end
    
    def get_with_verbatim_url(url)
      get(*recompose(url))
    end
    
    def recompose(url)
      u = URI.parse(url)
      [u.path.gsub(/^\/pasaporte/, ''), decode_qs(u.query)]
    end
end