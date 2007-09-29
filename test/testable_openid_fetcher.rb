# Implements OpenID::Fetcher. Will run the request through the application instead of calling
# out via HTTP
class TestableOpenidFetcher
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
    @server_poster = OpenidPoster.new("test_foo")
    @server_poster.setup # manually yes
    NetHTTPFetcher.requestor = @server_poster
  end
  
  def get(uri)
    @browser_getter.get relativized(uri)
    [uri, @browser_getter.response.body]
  end
  
  def post(uri, body)
    @server_poster.post relativized(uri), body
    [uri, @server_poster.response.body]
  end
  
  private
    def relativized(uri)
      # Here we need to replace the mount point URL otherwise
      # OpenID gets confused and actually posts into it
      # - Mosquito does not like that
      u = URI.parse(uri)
      unless (u.host == @browser_getter.request.http_host)
        raise ExternalResource, "OpenID consumer wants to have #{u}"
      end
      u.path.gsub(/^\/pasaporte/, '')
    end
end

# And this bitch is for Ruby Yadis (which slows the testing down on my G5 about 30 times, thanks folks)
class NetHTTPFetcher
  def self.requestor=(x)
    @requestor = x
  end
  
  def self.requestor
    @requestor
  end
  
  def initialize(no_op=20, no_op_two=20); end
    
  def get(url, params = nil)
    test_case = self.class.requestor
    
    test_case.request.headers.merge!(params)
    test_case.get(url)
    resp = test_case.response
    mokie = Camping::H.new
    mokie.headers, mokie.body = test_case.response.headers, test_case.response.body.to_s
    [url, mokie]
  end
end