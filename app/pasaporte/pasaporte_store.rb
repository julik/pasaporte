require 'openid/store/interface'
class PasaporteStore < ::OpenID::Store::Interface
  include ::Pasaporte::Models
  attr_accessor :pasaporte_domain
  
  def store_association(server_url, assoc)
    raise "Cannot save association without my own domain being set" unless @pasaporte_domain
    remove_association(server_url, assoc.handle)    
    Association.create(:server_url => server_url,
                       :handle     => assoc.handle,
                       :secret     => assoc.secret,
                       :issued     => assoc.issued,
                       :lifetime   => assoc.lifetime,
                       :assoc_type => assoc.assoc_type,
                       :pasaporte_domain => pasaporte_domain)
  end

  def get_association(server_url, handle=nil)
    raise "Cannot load association without my own domain being set" unless @pasaporte_domain
    assocs = if handle.blank?
        Association.find_all_by_server_url_and_pasaporte_domain(server_url, pasaporte_domain)
      else
        Association.find_all_by_server_url_and_handle_and_pasaporte_domain(server_url, handle, pasaporte_domain)
      end
      
    assocs.reverse.each do |assoc|
      a = assoc.from_record    
      if a.expires_in == 0
        assoc.destroy
      else
        return a
      end
    end if assocs.any?
    
    return nil
  end
  
  def remove_association(server_url, handle)
    raise "Cannot remove association without my own domain being set" unless pasaporte_domain
    Association.delete_all(['server_url = ? AND handle = ? AND pasaporte_domain = ?', server_url, handle, pasaporte_domain]) > 0
  end
  
  def use_nonce(server_url, timestamp, salt)
    raise "Cannot look for nonce without my own domain being set" unless pasaporte_domain
    return false if Nonce.find_by_server_url_timestamp_salt_and_pasaporte_domain(server_url, timestamp, salt, pasaporte_domain)
    return false if (timestamp - Time.now.to_i).abs > OpenID::Nonce.skew
    Nonce.create(:server_url => server_url, :timestamp => timestamp, :salt => salt)
    return true
  end
  
  def cleanup_nonces
    now = Time.now.to_i
    Nonce.delete_all(["timestamp > ? OR timestamp < ?", now + OpenID::Nonce.skew, now - OpenID::Nonce.skew])
  end

  def cleanup_associations
    now = Time.now.to_i
    Association.delete_all(['issued + lifetime > ?',now])
  end
end
