# name: restrict-moderator-access
# about: Restrict moderator access to user profiles and other private info
# version: 0.1
# authors: netarmy <misaka4e21@gmail.com>

after_initialize do

  UserGuardian.module_eval do
    def can_edit_user?(user)
      is_me?(user) || is_admin?
    end
    def can_edit_username?(user)
      return false if (SiteSetting.sso_overrides_username? && SiteSetting.enable_sso?)
      return true if is_admin?
      return false if SiteSetting.username_change_period <= 0
      is_me?(user) && (user.post_count == 0 || user.created_at > SiteSetting.username_change_period.days.ago)
    end

    def can_edit_email?(user)
      return false if (SiteSetting.sso_overrides_email? && SiteSetting.enable_sso?)
      return false unless SiteSetting.email_editable?
      return true if is_admin?
      can_edit?(user)
    end

    def can_edit_name?(user)
      return false if not(SiteSetting.enable_names?)
      return false if (SiteSetting.sso_overrides_name? && SiteSetting.enable_sso?)
      return true if is_staff?
      can_edit?(user)
    end
    
    def can_anonymize_user?(user)
      is_admin? && !user.nil? && !user.staff?
    end
  end

  AdminUserListSerializer.class_eval do
    def include_email?
      (scope.is_admin? && object.id == scope.user.id)
    end
  end
  AdminUserSerializer.class_eval do
    def include_email?
      (scope.is_admin? && object.id == scope.user.id)
    end
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
