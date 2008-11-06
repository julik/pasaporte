# A simple but effective CSRF protector
class TokenBox
  class Invalid < RuntimeError; end
  MAX_TOKENS, TOKEN_SIZE = 2, 64
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
    returning(Token.new(lifetime || WINDOW)) do | t |
      @heap ||= {}
      @heap[request] ||= []
      @heap[request].shift if @heap[request].length > MAX_TOKENS
      @heap[request] << t
    end
  end
  
  # Validate the token for a specific request URI
  def validate!(request, token)
    raise Invalid.new("no heap part") unless (@heap && @heap[request])
    @heap[request].reject!{|t| t.expired? }
    raise Invalid.new("no token found in heap") unless @heap[request].find{|e| e.to_s == token}
    @heap[request].reject!{|e| e.to_s == token }
  end
end