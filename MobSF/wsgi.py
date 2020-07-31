<<<<<<< HEAD
"""
WSGI config for MobSF project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/dev/howto/deployment/wsgi/
"""
import os
import warnings

from django.core.wsgi import get_wsgi_application

from whitenoise import WhiteNoise


warnings.filterwarnings('ignore', category=UserWarning, module='cffi')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MobSF.settings')

application = WhiteNoise(get_wsgi_application(),
                         root='static', prefix='static/')
=======
"""
WSGI config for MobSF project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/dev/howto/deployment/wsgi/
"""
import os
import warnings

from django.core.wsgi import get_wsgi_application

from whitenoise import WhiteNoise


warnings.filterwarnings('ignore', category=UserWarning, module='cffi')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MobSF.settings')

application = WhiteNoise(get_wsgi_application(),
                         root='static', prefix='static/')
>>>>>>> 0e25bd1b7f0ac52d875766e80a7158f5e5832e2f
