from urlparse import urljoin
from urllib import urlencode, urlopen
from django.db import models
from django.conf import settings
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django_cas.exceptions import CasTicketException, CasConfigException
# Ed Crewe - add in signals to delete old tickets
from django.db.models.signals import post_save
from datetime import datetime, timedelta
from django_cas import CAS

class SessionServiceTicket(models.Model):
    """ Handles a mapping between the CAS Service Ticket and the session key
        as long as user is connected to an application that uses the CASBackend
        for authentication
    """
    service_ticket = models.CharField('service ticket', max_length=255, primary_key=True)
    session_key = models.CharField('session key', max_length=40)

    class Meta:
        db_table = 'django_cas_session_service_ticket'
        verbose_name = 'session service ticket'
        verbose_name_plural = 'session service tickets'

    def get_session(self):
        """ Searches the session in store and returns it """
        session_engine = __import__(name=settings.SESSION_ENGINE, fromlist=['SessionStore'])
        SessionStore = getattr(session_engine, 'SessionStore')
        return SessionStore(session_key=self.session_key)

    def __unicode__(self):
        return self.service_ticket

@receiver(user_logged_in)
def map_service_ticket(sender, **kwargs):
    """ Creates the mapping between a session key and a service ticket after user
        logged in """
    request = kwargs['request']
    ticket = request.GET.get('ticket', '')
    if ticket:
        session_key = request.session.session_key
        SessionServiceTicket.objects.get_or_create(service_ticket=ticket,
                                            session_key=session_key)

@receiver(user_logged_out)
def delete_service_ticket(sender, **kwargs):
    """ Deletes the mapping between session key and service ticket after user
        logged out """
    request = kwargs['request']
    session_key = request.session.session_key
    SessionServiceTicket.objects.filter(session_key=session_key).delete()
        
class Tgt(models.Model):
    username = models.CharField(max_length = 255, unique = True)
    tgt = models.CharField(max_length = 255)
    created = models.DateTimeField(auto_now = True)

    def get_proxy_ticket_for(self, service):
        """Verifies CAS 2.0+ XML-based authentication ticket.

        Returns username on success and None on failure.
        """
        if not settings.CAS_PROXY_CALLBACK:
            raise CasConfigException("No proxy callback set in settings")

        try:
            from xml.etree import ElementTree
        except ImportError:
            from elementtree import ElementTree

        params = {'pgt': self.tgt, 'targetService': service}

        url = (urljoin(settings.CAS_SERVER_URL, 'proxy') + '?' +
               urlencode(params))

        page = urlopen(url)

        try:
            response = page.read()
            tree = ElementTree.fromstring(response)
            if tree.find(CAS + 'proxySuccess') is not None:
                return tree.find(CAS + 'proxySuccess/' + CAS + 'proxyTicket').text
            else:
                raise CasTicketException("Failed to get proxy ticket")
        finally:
            page.close()

class PgtIOU(models.Model):
    """ Proxy granting ticket and IOU """
    pgtIou = models.CharField(max_length = 255, unique = True)
    tgt = models.CharField(max_length = 255)
    created = models.DateTimeField(auto_now = True)

def get_tgt_for(user):
    if not settings.CAS_PROXY_CALLBACK:
        raise CasConfigException("No proxy callback set in settings")

    try:
        return Tgt.objects.get(username = user.username)
    except ObjectDoesNotExist:
        raise CasTicketException("no ticket found for user " + user.username)

def delete_old_tickets(**kwargs):
    """ Delete tickets if they are over 2 days old 
        kwargs = ['raw', 'signal', 'instance', 'sender', 'created']
    """
    sender = kwargs.get('sender', None)
    now = datetime.now()
    expire = datetime(now.year, now.month, now.day) - timedelta(days=2)
    sender.objects.filter(created__lt=expire).delete()
    
post_save.connect(delete_old_tickets, sender=PgtIOU)
post_save.connect(delete_old_tickets, sender=Tgt)
