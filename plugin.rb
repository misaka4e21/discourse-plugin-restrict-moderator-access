# name: restrict-moderator-access
# about: Restrict moderator access to user profiles and other private info
# version: 0.1
# authors: netarmy <misaka4e21@gmail.com>

after_initialize do
  UserGuardian.module_eval do
    def can_see_staff_info?(user)
      user && is_admin?
    end
  end
end
