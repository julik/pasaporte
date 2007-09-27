# Implements OpenID::Fetcher. Will run the request through the application instead of calling
# out via HTTP
class TestableOpenidFetcher
  class ExternalResource < RuntimeError; end

  # We need a separate Mosquito tester class for things that will
  # happen via POST, because this is a different flow - 
  # the requests of the server instead of the browser. 
  # If you post directly from the same test case you are destroying the
  # session ID that has been gotten by the simulated browser, that's why we use that.
  class OpenidPoster < Pasaporte::WebTest
    attr_reader :request, :response
    def test_foo; assert true; end
  end
  
  def initialize(test_case)
    @browser_getter = test_case
    @server_poster = OpenidPoster.new("test_foo")
    @server_poster.setup # manually yes
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