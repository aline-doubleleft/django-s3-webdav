from django.contrib.auth.models import User, check_password
from gdata.apps.service import AppsService
from gdata.docs.service import DocsService

DOMAIN = "doubleleft.com"
ADMIN_USERNAME = ""
ADMIN_PASSWORD = ""

class GoogleAppsBackend:
    """ Authenticate against Google Apps """
    def authenticate(self, username=None, password=None):
        user = None
        email = "{}@{}".format(username, DOMAIN)
        print email
        admin_email = "{}@{}".format(ADMIN_USERNAME, DOMAIN)
        print admin_email
        try:
            # Check user's password
            gdocs = DocsService()
            gdocs.email = email
            gdocs.password = password
            gdocs.ProgrammaticLogin()

            # Get the user object
            gapps = AppsService(domain=DOMAIN)
            gapps.ClientLogin(username=admin_email,
            password=ADMIN_PASSWORD,
            account_type='HOSTED', service='apps')
            guser = gapps.RetreiveUser(username)
            print guser
            user = User.objects.get_or_create(username=username)
            print user
            user.email = email
            user.last_name = guser.name.family_name
            user.first_name = guser.name.given_name
            user.is_active = not guser.login.suspended == 'true'
            user.is_superuser = guser.login.admin == 'true'
            user.is_staff = user.is_superuser
            user.save()
        except:
            pass

        return user

    def get_user(self, user_id):
        user = None
        try:
            user = User.objects.get(pk=user_id)
        except:
            pass

        return user


