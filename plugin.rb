# name: restrict-moderator-access
# about: Restrict moderator access to user profiles and other private info
# version: 0.1
# authors: netarmy <misaka4e21@gmail.com>

after_initialize do
  AdminUserListSerializer.class_eval do
    def include_email?
      (scope.is_admin? && object.id == scope.user.id) || scope.can_see_emails?
    end
  end
  AdminUserSerializer.class_eval do
    def can_see_ip?
      scope.is_admin? && object.id == scope.user.id
    end
    def ip_address
      object.ip_address.try(:to_s) if can_see_ip? else '127.233.233.233'
    end
    
    def registration_ip_address
      if can_see_ip? then
        object.ip_address.try(:to_s)
      else
        '127.233.233.233'
      end
    end
  end
end
