#!/usr/bin/env python3

import dns.exception
import dns.resolver
import logging
import os
import requests
import sys
import time

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())

if os.environ.get('CF_DEBUG'):
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

try:
    CF_HEADERS = {
        'X-Auth-Email': os.environ['CF_EMAIL'],
        'Authorization'  : 'Bearer ' + os.environ['CF_TOKEN'],
        'Content-Type': 'application/json',
    }
except KeyError:
    logger.error(" + Unable to locate Cloudflare credentials in environment!")
    sys.exit(1)

try:
    dns_servers = os.environ['CF_DNS_SERVERS']
    dns_servers = dns_servers.split()
except KeyError:
    dns_servers = False


def _has_dns_propagated(name, token):
    try:
        if dns_servers:
            custom_resolver = dns.resolver.Resolver()
            custom_resolver.nameservers = dns_servers
            dns_response = custom_resolver.resolve(name, 'TXT')
        else:
            dns_response = dns.resolver.resolve(name, 'TXT')

        for rdata in dns_response:
            if token in [b.decode('utf-8') for b in rdata.strings]:
                return True

    except dns.exception.DNSException as e:
        logger.debug(" + {0}. Retrying query...".format(e))

    return False

def tld(domain):  # thanks https://github.com/rossnick/letsencrypt-DNSMadeEasy-hook
    """Take likely domain"""
    if domain.count('.') > 1:
        return domain[domain.find('.') + 1:]
    else:
        return domain

# https://developers.cloudflare.com/api/resources/zones/methods/list/
def _get_zone_id(domain):
    url = f"https://api.cloudflare.com/client/v4/zones?name={tld(domain)}"
    r = requests.get(url, headers=CF_HEADERS)
    r.raise_for_status()
    return r.json()['result'][0]['id']


# https://api.cloudflare.com/#dns-records-for-a-zone-dns-record-details
def _get_txt_record_id(zone_id, name, token):
    url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records?type=TXT&name={1}&content={2}".format(zone_id, name, token)
    r = requests.get(url, headers=CF_HEADERS)
    r.raise_for_status()
    try:
        record_id = r.json()['result'][0]['id']
    except IndexError:
        logger.debug(" + Unable to locate record named {0}".format(name))
        return

    return record_id


# https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
def create_txt_record(args):
    domain, challenge, token = args
    logger.debug(' + Creating TXT record: {0} => {1}'.format(domain, token))
    logger.debug(' + Challenge: {0}'.format(challenge))
    # FIXME we should ask id once for same domain
    zone_id = _get_zone_id(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)

    record_id = _get_txt_record_id(zone_id, name, token)
    if record_id:
        logger.debug(" + TXT record exists, skipping creation.")
        return

    url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records".format(zone_id)
    payload = {
        'type': 'TXT',
        'name': name,
        'content': token,
        'ttl': 120,
    }
    r = requests.post(url, headers=CF_HEADERS, json=payload)
    r.raise_for_status()
    record_id = r.json()['result']['id']
    logger.debug(" + TXT record created, CFID: {0}".format(record_id))


# https://api.cloudflare.com/#dns-records-for-a-zone-delete-dns-record
def delete_txt_record(args):
    domain, token = args[0], args[2]
    if not domain:
        logger.info(" + http_request() error in letsencrypt.sh?")
        return

    zone_id = _get_zone_id(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)
    record_id = _get_txt_record_id(zone_id, name, token)

    if record_id:
        url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records/{1}".format(zone_id, record_id)
        r = requests.delete(url, headers=CF_HEADERS)
        r.raise_for_status()
        logger.debug(" + Deleted TXT {0}, CFID {1}".format(name, record_id))
    else:
        logger.debug(" + No TXT {0} with token {1}".format(name, token))


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    logger.debug(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.debug(' + ssl_certificate_key: {0}'.format(privkey_pem))
    return


def unchanged_cert(args):
    return


def invalid_challenge(args):
    domain, result = args
    logger.debug(' + invalid_challenge for {0}'.format(domain))
    logger.debug(' + Full error: {0}'.format(result))
    return


def create_all_txt_records(args):
    X = 3
    for i in range(0, len(args), X):
        create_txt_record(args[i:i+X])
    # give it 10 seconds to settle down and avoid nxdomain caching
    logger.info(" + Settling down for 10s...")
    time.sleep(10)
    for i in range(0, len(args), X):
        domain, token = args[i], args[i+2]
        name = "{0}.{1}".format('_acme-challenge', domain)
        while not _has_dns_propagated(name, token):
            # FIXME we should retry setting the record at least once. Or suggest so.
            logger.info(" + DNS not propagated, waiting 30s...")
            time.sleep(30)


def delete_all_txt_records(args):
    x = 3
    for i in range(0, len(args), x):
        delete_txt_record(args[i:i + x])

def startup_hook(args):
    return

def exit_hook(args):
    return


def main(argv):
    ops = {
        'deploy_challenge': create_all_txt_records,
        'clean_challenge' : delete_all_txt_records,
        'deploy_cert'     : deploy_cert,
        'unchanged_cert'  : unchanged_cert,
        'invalid_challenge': invalid_challenge,
        'startup_hook': startup_hook,
        'exit_hook': exit_hook
    }
    if argv[0] in ops:
        logger.info(" + CloudFlare hook executing: {0}".format(argv[0]))
        ops[argv[0]](argv[1:])

if __name__ == '__main__':
    main(sys.argv[1:])
