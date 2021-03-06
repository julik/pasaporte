# Implements OpenID::Fetcher. Will run the request through the mosquito test case instead of calling
# out via HTTP
class TestableOpenidFetcher
  # Will be raised when the fetcher tries to get a URL which is
  # not within the application being tested
  class ExternalResource < RuntimeError; end

  # We need a separate Mosquito tester class for things that will
  # happen via POST, because this is a different flow - 
  # the requests of the server instead of the browser. 
  # If you post directly from the same test case you are wiring yourself into the
  # session ID that has been gotten by the simulated browser, that's why we use that.
  class OpenidPoster < Pasaporte::WebTest
    attr_reader :request, :response
    def test_foo; assert true; end
  end
  
  def initialize(test_case)
    @browser_getter = test_case
    @browser_getter.request.headers['HTTP_HOST'] = 'test.host'
    @server_poster = OpenidPoster.new("test_foo")
    @server_poster.setup # manually yes
  end
  
  # This is used by OpenID lib 2
  def fetch(url, body=nil, headers=nil, redirect_limit=10)
    url, url_stringified = URI::parse(url), url.dup
    
    h = headers || {}
    
    raise_on_external url, @browser_getter
    
    camping_controller_with_response =  (body.blank? ? get(url.request_uri, h) : post(url.request_uri, h, body))
    ::OpenID::HTTPResponse._from_net_response(FakeResponse.new(camping_controller_with_response), url_stringified)
  end
  
  # An adapter to make a Mosquito response (Camping controller) behave like Net::HTTPResponse
  class FakeResponse < ::Net::HTTPResponse
    def initialize(mosquito_response)
      @the = mosquito_response
      super('1.0', @the.status.to_s, 'Found') # http version, resp code and message
      flat_headers = @the.headers.inject({}) { |n, k| n.merge k[0] => k[1].to_s } rescue {}
      initialize_http_header(flat_headers)
    end
    
    def body
      @the.body
    end
    
    def code
      @the.status.to_s
    end
  end
  
  private
    def get(uri, headers = {})
      Pasaporte::LOGGER.debug "OpenID requested GET on #{uri}"
      @browser_getter.get relativized(uri) # this fails somehow
      @browser_getter.response
    end
    
    def post(uri, headers = {}, body = '')
      Pasaporte::LOGGER.debug "OpenID requested POST on #{uri}"
      @server_poster.post relativized(uri), body
      @server_poster.response
    end
    
    def relativized(uri)
      # Here we need to replace the mount point URL otherwise
      # OpenID gets confused and actually posts into it
      # - Mosquito does not like that
      u = URI.parse(uri)
      u.path.gsub(/^\/pasaporte/, '')
    end
    
    # Check if we are calling to the outside world
    def raise_on_external(uri, testcase)
      unless ((uri.host == testcase.request.http_host) || uri.host.blank?)
        raise ExternalResource, "Called out to external resource: OpenID consumer wants to have #{uri}"
      end
    end
end