# A simple but effective CSRF protector
class TokenBox
  class Invalid < RuntimeError; end
  MAX_TOKENS, TOKEN_SIZE = 4, 28
  CHARS = [*'A'..'Z'] + [*'0'..'9'] + [*'a'..'z']
  WINDOW = 10.minutes # Gone in 60 seconds
  
  class Token
    attr_reader :token
    alias_method :to_s, :token
    
    def initialize(lifetime)
      @will_expire = Time.now.utc + lifetime
      @token = (0...TOKEN_SIZE).inject("") { |ret,_| ret << CHARS[rand(CHARS.length)] }
    end
    
    def expired?
      @will_expire < Time.now.utc
    end
    
    def inspect
      "#{@token}:#{'exp' if expired?}"
    end
  end
  
  # Procure a CSRF token for a specific request URI
  def procure!(request, lifetime = nil)
    @heap ||= {}
    @heap[request] ||= []
    @heap[request].shift if @heap[request].length > MAX_TOKENS
    @heap[request] << Token.new(lifetime || WINDOW)
  end
  
  # Validate the token for a specific request URI
  def validate!(request, token)
    raise Invalid unless (@heap && @heap[request])
    @heap[request].reject!{|t| t.expired? }
    raise Invalid unless @heap[request].reject!{|t| t.token == token}
  end
end