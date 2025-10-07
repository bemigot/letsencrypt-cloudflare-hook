# CloudFlare hook for `dehydrated`

This is a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client [dehydrated](https://github.com/lukas2511/dehydrated)
(once known as `letsencrypt.sh`) that allows you to use [Cloudflare](https://www.cloudflare.com/)
DNS records to respond to `dns-01` challenges.
Requires Python 3.6+ and your Cloudflare account e-mail and API token in the environment.

## Installation

```bash
$ cd ~
$ git clone https://github.com/dehydrated-io/dehydrated.git
$ cd dehydrated
$ mkdir hooks
$ git clone https://github.com/bemigot/letsencrypt-cloudflare-hook.git hooks/cloudflare

$ pip install -r hooks/cloudflare/requirements.txt
```

## Configuration

Your account's CloudFlare email and API key are expected to be in the environment, see below.

If you want more information about what is going on while the hook is running:
```
$ export CF_DEBUG='true'
```

These statements can be placed in `dehydrated/config`, which is automatically sourced by `dehydrated` on startup:

```bash
D_CONFIG=../dehydrated/config
cat >> $D_CONFIG << EoConfig
CHALLENGETYPE='dns-01'
HOOK=hooks/cloudflare/hook.py
export CF_EMAIL=me@example.com
export CF_TOKEN=K9-uX2HyUjeWg5AhAb
EoConfig
```


## Usage

```
$ ./dehydrated -c -d example.com

Processing example.com
 + Signing domains...
 + Creating new directory /home/user/dehydrated/certs/example.com ...
 + Generating private key...
 + Generating signing request...
 + Requesting challenge for example.com...
 + CloudFlare hook executing: deploy_challenge
 + DNS not propagated, waiting 10s...
 + DNS not propagated, waiting 10s...
 + Responding to challenge for example.com...
 + CloudFlare hook executing: clean_challenge
 + Challenge is valid!
 + Requesting certificate...
 + Checking certificate...
 + Done!
 + Creating fullchain.pem...
 + CloudFlare hook executing: deploy_cert
 + ssl_certificate: ~/dehydrated/certs/example.com/fullchain.pem
 + ssl_certificate_key: ~/dehydrated/certs/example.com/privkey.pem
 + Done!
```

## Author's note
[February 04, 2016: From StartSSL to Let's Encrypt, using CloudFlare DNS](http://kappataumu.com/articles/letsencrypt-cloudflare-dns-01-hook.html).
