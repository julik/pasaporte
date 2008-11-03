# This is something the JanRain folks omitted. The test suite for OpenID that
# is in Pasaporte takes 26 seconds to run with the standard library and
# 19 seconds with this. Lo and behold.
begin
  require 'openssl'
  module ::OpenID::CryptUtil
    def self.hmac_sha1(key, text)
      OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('SHA1'), key, text).to_s
    end
    def self.sha1(s)
      OpenSSL::Digest::SHA1.new(s).digest.to_s
    end
  end
  
  class OpenID::DiffieHellman
    # Convert any number of ints to OpenSSL bignums
    def self._bignos(*args)
      # The trick here is that Integer#to_bn does not work because you need to feed strings
      args.map do |a| 
        raise ArgumentError, "Cannot convert nil to OpenSSL bignum!" if a.nil?
        OpenSSL::BN.new(a.to_s)
      end
    end
    
    def self.powermod(base, power, mod)
      base, power, mod = _bignos(base, power, mod)
      base.mod_exp(power, mod).to_i
    end
  end
rescue LoadError
  $stderr.puts "Pasaporte will use slow ruby crypto. Please consider installing OpenSSL for Ruby."
end

# Redirect the logging to Pasaporte
# module ::OpenID::Util
#  def self.log(message)
#    Pasaporte::LOGGER.info('OpenID: ' + message)
#  end
# end