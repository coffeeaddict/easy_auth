# EasyAuth

module EasyAuth
  def self.included(base)
    base.extend ClassMethods
  end

  module ClassMethods
    def acts_as_authentic
      class_eval <<-EOC
        before_create :hash_password
        before_update :hash_new_password

        attr_accessor :new_password, :password_confirm

        def hash_password
          return if self.password.nil? or !self.password
          if self.password == self.password_confirm
            hash = ActiveRecord::Base.hashed_password( self.password )
            self.password = hash
        
          else
            self.errors.add("password", "Passwords do not match");
            # stop the chain, return false
            return false
        
          end
        end
    
        def hash_new_password
          if self.new_password
            if ( self.new_password == self.password_confirm )
              hash = ActiveRecord::Base.hashed_password( self.new_password )
              self.password = hash

            else
              self.errors.add("password", "Newly supplied passwords mismatch")
              # stop the chain, return false
              return false

            end
          end
        end
      EOC
    end

    def hashed_password(password)
      return Digest::SHA512.hexdigest(password.to_s + EASY_AUTH_SALT)
    end

    def authenticate(username, password)
      begin
        return find( :first,
                     :conditions =>
                     [ "username = ? AND password = ?",
                       username,
                       hashed_password(password)
                     ]
                   )
      rescue Exception => ex
        return nil
      end
    end
  end
end

module EasyAuthController
  def self.included(base)
    base.extend ClassMethods
  end

  module ClassMethods
    def acts_as_authenticator_for(klass)
      class_eval <<-EOC
        def current_user
          return nil unless session[:user]
          return #{klass}.find(session[:user])
        end
        def current_user=(user)
          session[:user] = user.id
        end
      EOC
    end
  end
end

class ActiveRecord::Base
  include EasyAuth
end

class ActionController::Base
  include EasyAuthController
end
