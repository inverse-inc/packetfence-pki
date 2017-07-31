# Description

PacketFence-pki is a light and simple pki.

# Requirements

PacketFence-pki requires the following:

Django (>= 1.6)
Django REST framework 
Django bootstrap3

# Install

Djando debian package is available but you need to have django >= 1.6

If you distribution have Django 1.6 available, install it, if no then manually install it:


## Install Pip, the Python package manager.

```
sudo apt-get install python-pip
```

Optionally, but recommended, upgrade pip, using itself:

```
sudo pip install -U pip
```

## Install the latest stable version of Django:

```
sudo pip install Django
```

To install a specific version, add a requirement specifier like this:

```
sudo pip install Django==1.6.6
```

## Install Django REST Framework

```
sudo pip install djangorestframework
```

## Install Django bootstrap3

```
sudo pip install django-bootstrap3
```

# Setup

## Database

By default packetfence-pki will use the local sqlite database but you can use MySQL if needed.
In order to do that edit the file settings.py and uncomment this:

```
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'pfpki',
        'USER': 'pf',
        'PASSWORD': 'pf',
        'HOST': '127.0.0.1',
        'PORT': '',
    }
}
```

and comment this:

```
#DATABASES = {
#    'default': {
#        'ENGINE': 'django.db.backends.sqlite3',
#        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
#    }
#}
```

Next create the pfpki database:

```
mysql -u root -p -e "CREATE DATABASE pfpki'"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON pfpki.* TO 'pf'@'%' IDENTIFIED BY 'pf'"
mysql -u root -p -e "FLUSH PRIVILEGES"`
```

Then sync the db (in /usr/local/packetfence-pki):

```
python manage.py syncdb --noinput
```

## Initial setup

Connect your browser to https://@ip:9393 and use the default username and password (admin/p@ck3tf3nc3).


