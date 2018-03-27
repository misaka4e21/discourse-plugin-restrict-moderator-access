# name: restrict-moderator-access
# about: Restrict moderator access to user profiles and other private info
# version: 0.1
# authors: misaka4e21 <misaka4e21@gmail.com>

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
    alias :can_deactivate? :can_suspend?
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

  PostGuardian.module_eval do
    alias :back_can_see_post? :can_see_post?
    def can_see_post?(post)
      enabled =  SiteSetting.restrict_access_visible_only_to_self_and_staff
      group = Group.find_by("lower(name) = ?", SiteSetting.restrict_access_visible_only_to_self_and_staff_group.downcase)
      if back_can_see_post?(post)
        if (not @user.is_anonymous) and enabled && group && GroupUser.where(user_id: post.user.id, group_id: group.id).exists?
          if @user.id == post.user.id || @user.is_staff?
            true # show for staff and the author
          else
            false # hide for others
          end
        else
          true # not restricted
        end
      else
        false # already hidden
      end
    end
  end

  TopicGuardian.module_eval do
    alias :back_can_see_topic? :can_see_topic?
    def can_see_topic?(topic)
      enabled =  SiteSetting.restrict_access_visible_only_to_self_and_staff
      group = Group.find_by("lower(name) = ?", SiteSetting.restrict_access_visible_only_to_self_and_staff_group.downcase)
      if back_can_see_topic?(topic)
        if enabled && group && GroupUser.where(user_id: topic.user.id, group_id: group.id).exists?
          if (not @user.is_anonymous) and @user.id == topic.user.id || @user.is_staff?
            true # show for staff and the author
          else
            false # hide for others
          end
        else
          true # not restricted
        end
      else
        false # already hidden
      end
    end
  end

  BasicTopicSerializer.class_eval do
    def visible
      if object.visible
        enabled =  SiteSetting.restrict_access_visible_only_to_self_and_staff
        group = Group.find_by("lower(name) = ?", SiteSetting.restrict_access_visible_only_to_self_and_staff_group.downcase)
        if enabled && group && GroupUser.where(user_id: object.user.id, group_id: group.id).exists?
          if (not scope.user.is_anonymous) and scope.user.id == object.user.id || scope.user.is_staff?
            true
          else
            false
          end
        else
          true
        end
      else
        false
      end
    end
  end
end
