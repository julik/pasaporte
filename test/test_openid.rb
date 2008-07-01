require File.dirname(__FILE__) + '/helper'
require 'fileutils'
require File.dirname(__FILE__) + '/testable_openid_fetcher'
require 'openid/store/filesystem'

class Object
  def own_methods
    raise (methods - Object.instance_methods).inspect
  end
end

class TestOpenid < Pasaporte::WebTest
  # We have to open up because it's the Fecther that's going
  # to make requests
  attr_reader :request, :response
  fixtures :pasaporte_profiles

  def setup
    super
    @fetcher = TestableOpenidFetcher.new(self)
    
    OpenID.fetcher = @fetcher
    
    # You MIGHT have thought that using a MemoryStore would be faster. HA!
    # Laughable, but it's actually much slower.
    # MemoryStore - 29s, FilesystemStore - 18s
    @store = OpenID::Store::Filesystem.new('openid-consumer-store')
    @openid_session = {}
    init_consumer
    
    @request.domain = 'test.host'
    
    @trust_root = 'http://tativille.fr/wiki'
    @return_to = 'http://tativille.fr/wiki/signup'
    @hulot = Profile.find(1)
  end
  
  def teardown
    # Delete all the associations created during the test case
    JulikState::State.delete_all; Association.delete_all; Approval.delete_all; Throttle.delete_all
    # Delete the store
    FileUtils.rm_rf('openid-consumer-store')
    # Call super for flexmock a.o.
    super
  end
  
  def test_default_discovery_page_sports_right_server_url
    get '/monsieur-hulot'
    assert_response :success
    assert_select 'link[rel=openid.server]', true do | s |
      s = s.pop
      assert_equal "http://test.host/pasaporte/monsieur-hulot/openid", s.attributes["href"],
        "Should contain the delegate address for Monsieur Hulot"
    end
    assert_select 'link[rel=openid.delegate]', true do | s |
      s = s.pop
      assert_equal "http://test.host/pasaporte/monsieur-hulot/openid", s.attributes["href"],
        "Should contain the endpoint address for Monsieur Hulot"
    end
  end
  
  def test_in_which_tativille_begins_association_and_gets_a_proper_next_step_url
    assert_equal 'test.host', @request['SERVER_NAME']
    
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    assert_kind_of OpenID::Consumer::CheckIDRequest, req
    assert_kind_of OpenID::OpenIDServiceEndpoint, req.endpoint
    assert_equal "http://test.host/pasaporte/monsieur-hulot/openid", req.endpoint.server_url
    assert_equal "http://test.host/pasaporte/monsieur-hulot", req.endpoint.claimed_id
    
    # In this test we only get a next step URL
    next_step_url = req.redirect_url(@trust_root, @return_to, immediate=false)
    assert_nothing_raised("The URL received from the server should be parseable") do
      next_step_url = URI.parse(next_step_url)
    end
    
    assert_equal "http", next_step_url.scheme
    assert_equal "test.host", next_step_url.host
    
    response_params = decode_qs(next_step_url.query)

    assert_match(/#{Regexp.escape(@return_to + '?openid1_claimed_id=')}(.+)#{Regexp.escape('&rp_nonce=')}(.+)/, 
      response_params["openid.return_to"],
      "The return_to should be the one of the signup with a nonce")
    assert_equal "http://test.host/pasaporte/monsieur-hulot/openid",
      response_params["openid.identity"], "The identity is the server URL in this case"
    assert_equal "checkid_setup", response_params['openid.mode'], 
      "The current mode is checkid_setup"
  end
  
  def test_in_which_monsieur_hulot_is_not_logged_in_and_asked_for_login_after_setup
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    assert_kind_of OpenID::Consumer::CheckIDRequest, req
    assert_nothing_raised { get_with_verbatim_url req.redirect_url(@trust_root, @return_to) }
    assert_response :redirect
    assert_redirected_to '/monsieur-hulot/signon'
    assert_not_nil @state.pending_openid, "A pending OpenID request should have been "+
      "placed in the session"
    assert_kind_of OpenID::Server::CheckIDRequest, @state.pending_openid
  end
  
  def test_in_which_monsieur_hulot_is_asked_for_setup_decisions_after_logging_in
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    assert_nothing_raised { get_with_verbatim_url req.redirect_url(@trust_root, @return_to) }
    assert_response :redirect
    assert_redirected_to '/monsieur-hulot/signon', "Monsieur should be asked to login"
    
    prelogin!
    assert_response :redirect
    assert_redirected_to '/monsieur-hulot/openid',
      "The redirection should be to the continuation of the OpenID procedure"
    
    assert_nothing_raised { follow_redirect }
    assert_response :redirect
    
    assert_redirected_to '/monsieur-hulot/decide',
      "Should send Monsieur Hulot to the page where he will confirm himself trusting the Tativille"
    assert_not_nil @state.pending_openid,
      "The state should contain the OpenID request to be processed"
  end
  
  def test_in_which_monsieur_hulot_blindly_trusts_tativille
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    assert_nothing_raised { get_with_verbatim_url req.redirect_url(@trust_root, @return_to) }
    prelogin!
    
    follow_redirect # back to openid
    assert_redirected_to '/monsieur-hulot/decide', "Should send Monsieur Hulot to the page " +
      "where he will confirm himself trusting the Tativille"
    follow_redirect # to decide
    
    assert_select 'h2' do | e |
      assert_equal "<h2>Please approve <b>http://tativille.fr/wiki</b></h2>", e.to_s
    end
    
    post '/monsieur-hulot/decide'
    assert_redirected_to '/monsieur-hulot/openid',
      "Monsieur Hulot should be redirected back to the openid workflow page after approving"
    
    @hulot.reload
    approval = @hulot.approvals[0]
    assert_kind_of Approval, approval, "An approval should have been made"
    assert_equal @trust_root, approval.trust_root, "The approval approves tativille"
  end
  
  def test_in_which_monsieur_hulot_decides_not_to_trust_tativille
    prelogin!
    
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    assert_nothing_raised { get_with_verbatim_url req.redirect_url(@trust_root, @return_to) }
    
    assert_redirected_to '/monsieur-hulot/decide',
      "Should send Monsieur Hulot to the page where he will confirm himself trusting the Tativille"
    follow_redirect # to decide
    
    assert_select 'h2' do | e |
      assert_equal "<h2>Please approve <b>http://tativille.fr/wiki</b></h2>", e.to_s
    end
    
    post '/monsieur-hulot/decide', :nope => "Oh Non!"
    red, path, qs = redirect_url_path_and_params
    
    assert_equal '/wiki/signup', path, 
      "The taken decision should immediately send Monsieur Hulot back to the signup page"
    assert_equal 0, Approval.count, "No Approvals should have been issued"
    assert_kind_of OpenID::Consumer::CancelResponse, @consumer.complete(qs, red), "The response is negative"
  end
  
  def test_in_which_monsieur_hulot_already_approved_tativille_and_is_logged_in
    prelogin!; preapprove!
    
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot", immediate = false)
    assert_nothing_raised { get_with_verbatim_url req.redirect_url(@trust_root, @return_to) }
    
    redir_url, path, qs = redirect_url_path_and_params
    
    assert_kind_of OpenID::Consumer::SuccessResponse, @consumer.complete(qs, redir_url), "The response is positive"
    assert_equal '/wiki/signup', path, "This should be the path to the wiki signup"
  end
  
  def test_in_which_monsieur_hulot_uses_immediate_mode_and_the_mode_totally_works
    prelogin!; preapprove!
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    assert_nothing_raised do 
      get_with_verbatim_url req.redirect_url(@trust_root, @return_to, true)
    end
    red, path, qs = redirect_url_path_and_params
    
    openid_resp = @consumer.complete(qs, red)
    assert_kind_of OpenID::Consumer::SuccessResponse, openid_resp
  end

  def test_in_which_monsieur_hulot_uses_immediate_mode_but_needs_to_login_first
    preapprove!
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    assert_nothing_raised do 
      get_with_verbatim_url req.redirect_url(@trust_root, @return_to, true)
    end
    red, path, qs = redirect_url_path_and_params
    openid_resp = @consumer.complete(qs, red)
    
    assert_kind_of OpenID::Consumer::SetupNeededResponse, openid_resp, "Setup is needed for this action"
    assert_not_nil qs["openid.user_setup_url"], "The setup URL should be passed"
    
    setup_path, setup_qs = redirect_path_and_params(qs["openid.user_setup_url"])
    assert_equal "/pasaporte/monsieur-hulot/signon", setup_path, "The setup path is the signon"
    
    post '/monsieur-hulot/signon', {:pass => 'monsieur-hulot'.reverse}.merge(setup_qs)
    assert_response :redirect
    assert_redirected_to "/monsieur-hulot/openid",
      "Monsieur is now out of the immediate mode so we continue on to the openid process"
    follow_redirect
    red, path, qs = redirect_url_path_and_params
    
    assert_kind_of OpenID::Consumer::SuccessResponse, @consumer.complete(qs, red),
      "Monsieur has now authorized Tativille, albeit not immediately"
  end

  def test_in_which_monsieur_hulot_uses_immediate_mode_but_needs_to_approve_first
    prelogin!
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    assert_nothing_raised do 
      get_with_verbatim_url req.redirect_url(@trust_root, @return_to, true)
    end
    path, qs = redirect_path_and_params
    openid_resp = @consumer.complete(qs, path)
    
    assert_kind_of OpenID::Consumer::SetupNeededResponse, openid_resp, "Setup is needed for this action"
    assert_not_nil qs["openid.user_setup_url"], "The setup URL should be passed"
    
    setup_path, setup_qs = redirect_path_and_params(qs["openid.user_setup_url"])
    assert_equal "/pasaporte/monsieur-hulot/decide", setup_path, "The setup path is /decide"
    
    get '/monsieur-hulot/decide', setup_qs
    assert_response :success
    post '/monsieur-hulot/decide'
    assert_response :redirect
    assert_redirected_to '/monsieur-hulot/openid'
    follow_redirect
    
    path, qs = redirect_path_and_params
    assert_kind_of OpenID::Consumer::SuccessResponse, @consumer.complete(qs, path),
      "Monsieur has now authorized Tativille, albeit not immediately"
  end
  
  def test_in_which_monsieur_hulot_forgets_his_password_and_tativille_gets_a_refusal
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    assert_nothing_raised { get_with_verbatim_url req.redirect_url(@trust_root, @return_to) }
    assert_redirected_to '/monsieur-hulot/signon'
    (Pasaporte::MAX_FAILED_LOGIN_ATTEMPTS + 1).times do
      post '/monsieur-hulot/signon', :pass => 'cartouche'
    end
    puts @response.body
    assert_response :redirect
    path, qs = redirect_path_and_params
    assert_kind_of OpenID::Consumer::CancelResponse, @consumer.complete(qs, path),
      "Monsieur Hulot is denied authorization with Tativille after failing so miserably"
  end

  def test_in_which_monsieur_hulot_has_delegated
    d = "http://leopenid.fr/endpoint"
    
    begin
      @hulot.update_attributes :openid_delegate => d, :openid_server => d
      
      err = assert_raise(TestableOpenidFetcher::ExternalResource, "Should go out looking for openid") do
        @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
      end
      assert_equal "OpenID consumer wants to have http://leopenid.fr/endpoint", err.message 
    ensure
      @hulot.update_attributes :openid_delegate => nil, :openid_server => nil
    end
  end
  
  def test_in_which_monsieur_hulot_is_throttled_and_gets_rejected_at_once
    Throttle.set!(@request.to_hash)
    req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    assert_nothing_raised { get_with_verbatim_url req.redirect_url(@trust_root, @return_to) }
    assert_response :redirect
    path, qs = redirect_path_and_params
    assert_kind_of OpenID::Consumer::CancelResponse, @consumer.complete(qs, path),
      "Monsieur Hulot is instantly denied authorization with Tativille because he is throttled"
    assert_nil @state.pending_openid, "No OpenID request should be left dangling at this point"
  end
  
  def test_in_which_tativille_uses_dumb_mode
    # prelogin!; preapprove!
    # dumb = OpenID::DumbStore.new("les-vacances")
    # @consumer = OpenID::Consumer.new(@openid_session, dumb)
    # 
    # req = @consumer.begin("http://test.host/pasaporte/monsieur-hulot")
    # assert_nothing_raised { get_with_verbatim_url req.redirect_url(@trust_root, @return_to) }
    # path, qs = redirect_path_and_params
    # assert_equal '/wiki/signup', path, "This should be the path to the wiki signup"
    # assert_kind_of OpenID::SuccessResponse, @consumer.complete(qs), "The response is positive"
    flunk
  end
  
  private
    # Prelogins Monsieur Hulot into Pasaporte
    def prelogin!
      post '/monsieur-hulot/signon', :pass => 'monsieur-hulot'.reverse
    end

    # Preapproves tativille.fr as a site Monsieur Hulot trusts
    def preapprove!
      @hulot.approvals.create! :trust_root=>@trust_root
    end
    
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