# Make an array of backends and try to authenticate against them all until true is returned.
# Otherwise deny.
class Pasaporte::Auth::Cascade
  attr_reader :backends
  def initialize
    @backends = []
  end
  
  def call(u, p, d)
    @backends.each do | b | 
      Pasaporte::LOGGER.info("Running cascade auth against #{b}")
      b.call(u,p,d) || next
    end
    false
  end
end