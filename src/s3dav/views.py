import base64
import re
from django.http import HttpResponse, Http404
from django.contrib.auth.models import User, check_password

from s3dav.django_webdav import DavServer
from s3dav.server import S3DavServer
from s3dav.models import S3Account
from django.conf import settings

from gdata.apps.service import AppsService
from gdata.docs.service import DocsService
from gdata.service import BadAuthentication

def notfound(request, **kw):
    raise Http404

def log_error(func):
    def __w(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            import traceback
            traceback.print_exc()
            raise
    return __w

@log_error
def webdav_export(request, path, server_class=DavServer):
    '''Default Django-WebDAV view.'''
    return server_class(request, path).get_response()

def simple_auth(request):
    username = None
    password = None
    
    auth = request.META.get('HTTP_AUTHORIZATION')
    if auth:
        auth = auth.split()
        if len(auth) == 2 and auth[0].lower() == 'basic':
            username, password = base64.b64decode(auth[1]).split(':')
    
    if not username or not password:
        return
    aws_key = username
    aws_secret = password

    try:
        # Check if user already exist in django
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        try:
        # Check user's password
            gdocs = DocsService()
            gdocs.email = username
            gdocs.password = password
            gdocs.ProgrammaticLogin()
        except BadAuthentication:
            raise Http404('User or password does not match!')

        # We create a new user right from here
        gapps = AppsService(domain=settings.DOMAIN)
        gapps.ClientLogin(username=settings.ADMIN_USERNAME,
        password=settings.ADMIN_PASSWORD,
        account_type='HOSTED', service='apps')
        guser = gapps.RetrieveUser(username.split('@')[0])
        user = User.objects.create(username=username)
        user.set_password = password
        user.email = username
        user.last_name = guser.name.family_name
        user.first_name = guser.name.given_name
        user.is_active = not guser.login.suspended == 'true'
        user.is_superuser = guser.login.admin == 'true'
        user.is_staff = user.is_superuser
        user.save()
        
        try:
            # We check again for the newly created user
            user = User.objects.get(username=username)
        except:
            user = None

    if user:
        try:    
            # Here we first try to check if IAM associated with this account exist 
            account = S3Account.objects.get(user=user)
            aws_key = account.aws_access_key
            aws_secret = account.aws_secret
        except S3Account.DoesNotExist:
            # We associate the new gapps account with an AWS key
            account = S3Account.objects.create(user=user,aws_access_key=settings.AWS_KEY_DEFAULT,aws_secret=settings.AWS_SECRET_DEFAULT)       
            aws_key = account.aws_access_key
            aws_secret = account.aws_secret

    request.aws_key = aws_key
    request.aws_secret = aws_secret
    
@log_error
def export(request, bucket=None, key=None):
    if re.search(r'\._[^/]+$', key) and (request.method in ('OPTIONS', 'PROPFIND')):
        raise Http404
    simple_auth(request)
    if (not getattr(request, 'aws_key', None) or 
        not getattr(request, 'aws_secret', None)):
        realm = 'WebDAV'
        response = HttpResponse(status=401)
        response['WWW-Authenticate'] = 'Basic realm="%s"' % realm
        return response

    path = '%s/%s' % (bucket, key)
    return webdav_export(request, path, server_class=S3DavServer)
