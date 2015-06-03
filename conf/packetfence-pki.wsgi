#!/usr/local/bin/python
import os, sys
sys.path.append('/usr/local/pf/pki')
sys.path.append('/usr/local/pf/pki/inverse')
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'  # this is your settings.py file
os.environ['PYTHON_EGG_CACHE'] = '/tmp'

import django.core.wsgi

application = django.core.wsgi.get_wsgi_application()
