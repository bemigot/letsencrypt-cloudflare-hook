# CloudFlare hook for `dehydrated`

This is a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client [dehydrated](https://github.com/lukas2511/dehydrated) (previously known as `letsencrypt.sh`) that allows you to use [CloudFlare](https://www.cloudflare.com/) DNS records to respond to `dns-01` challenges. Requires Python and your CloudFlare account e-mail and API key being in the environment.

## Installation

```
$ cd ~
$ git clone https://github.com/lukas2511/dehydrated
$ cd dehydrated
$ mkdir hooks
$ git clone https://github.com/kappataumu/letsencrypt-cloudflare-hook hooks/cloudflare

$ pip install -r hooks/cloudflare/requirements.txt
```

## Configuration

Your account's CloudFlare email and API key are expected to be in the environment, so make sure to:

```
$ export CF_EMAIL='user@example.com'
$ export CF_TOKEN='K9uX2HyUjeWg5AhAb'
```

Optionally, you can specify the DNS servers to be used for propagation checking via the `CF_DNS_SERVERS` environment variable (props [bennettp123](https://github.com/bennettp123)):

```
$ export CF_DNS_SERVERS='8.8.8.8 8.8.4.4'
```

If you want more information about what is going on while the hook is running:

```
$ export CF_DEBUG='true'
```

Alternatively, these statements can be placed in `dehydrated/config`, which is automatically sourced by `dehydrated` on startup:

```
echo "CHALLENGETYPE='dns-01'"
echo "HOOK=hooks/cloudflare/hook.py"
echo "export CF_EMAIL=user@example.com" >> config
echo "export CF_TOKEN=K9-uX2HyUjeWg5AhAb" >> config
echo "export CF_DEBUG=true" >> config
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

## Further reading
If you want some prose to go with the code, check out the relevant blog post here: [February 04, 2016: From StartSSL to Let's Encrypt, using CloudFlare DNS](http://kappataumu.com/articles/letsencrypt-cloudflare-dns-01-hook.html).
