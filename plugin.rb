# name: restrict-moderator-access
# about: Restrict moderator access to user profiles and other private info
# version: 0.1
# authors: netarmy <misaka4e21@gmail.com>

after_initialize do
  UserGuardian.module_eval do
     def can_delete_user?(user)
       return false if user.nil? || user.admin?
       if is_me?(user)
         user.post_count <= 1
       else
         is_admin? && (user.first_post_created_at.nil? || user.first_post_created_at > SiteSetting.delete_user_max_post_age.to_i.days.ago)
       end
     end


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
  Guardian.class_eval do
    def can_see_emails?
      (is_me?(@user) || is_admin?) && @can_see_emails
    end
    
    def can_suspend?(user)
      user && is_admin? && user.regular?
    end
  end
  AdminUserSerializer.class_eval do
    def can_see_ip?
      scope.is_admin?
    end
    def ip_address
      if can_see_ip?
        object.ip_address.try(:to_s) 
      else
        ''
      end
    end
  
    def registration_ip_address
      if can_see_ip?
        object.registration_ip_address.try(:to_s)
      else
        ''
      end
    end
  end
end
