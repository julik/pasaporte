= Onde está seu pasaporte?

This is Pasaporte, a small identity server with a colored bar on top. It's in the style
of Crowd (but smaller). Will act as a mediator between OpenID and arbitary services where
users are distinguished by their nickname (login), their password and a domain name.

== The idea

Pasaporte brings OpenID to the traditional simplicity of

 is_a_villain = check_password(login, password, domain)

The only thing you WILL need to change is the AUTH constant. It should contain the proc
that, when called, will return true or false. Yes, it's that simple. All the negotiation
smorgasbord, profile editing, encryptodecryption and other electrabombastic niceties are
going to be taken care of.

Should the password become stale or should the authentication backend say that it no
longer has the user in question the authorization tokens are immediately revoked, and any
authorization requests will be denied.

== Using SSL

It is recommended that you run pasaporte in full SSL mode. However,
some OpenID consumers disallow OpenID providers with self-signed (i.e. free)
SSL certificates. Pasaporte mitigates this by offering the "partial SSL" mode. When turned on,
only the signon page (where the password is entered) and subsequent pages with which the user
interacts will be protected with SSL encryption, while the public OpenID endpoint will NOT be
SSL-enabled. Same is true for the server-server step of OpenID handshake.

This will allow even stricter providers to use Pasaporte servers.

When partial SSL is turned on, the profile page (OpenID identity) will forcibly be made
unencrypted (will redirect to non-secure port).

Partial SSL is disabled by default - to enable set PARTIAL_SSL to true.

== Current issues

As of now, we are not aware of sites that cannot consume OpenID from Pasaporte.

== Configuration

The adventurous among us can override the defaults (Pasaporte constants) by placing a
hash-formatted YAML file called "config.yml" in the pasaporte dir. And don't ask me what
a "hash-formatted YAML file" is, because if you do you are not adventurous.

Here the rundown of the config parameters:

MAX_FAILED_LOGIN_ATTEMPTS - after how many login attempts the user will be trottled
THROTTLE_FOR - Trottle length in seconds
ALLOW_DELEGATION - if set to true, the user will be able to redirect his OpenID
SESSION_LIFETIME - in seconds - how long does a session remain valid
PARTIAL_SSL - see above
HTTP_PORT - if partial SSL is used, the port on which the standard version runs
SSL_PORT - if partial SSL is used, the port on which the secure version runs

== Profiles

Pasaporte allows the user to have a simple passport page, where some info can be placed
for people who follow the OpenID profile URL. Sharing the information is entirelly optional.

== The all-id

The login that you use is ultimately the nickname that comes in the URL. For that reason
no other login name can be entered in the form. However the user still can verify that
it's his nickname and change it should he need to (or if he mistyped).

In essence, Pasaporte offers a page for any nickname and shows an identitifer in this
page that allows the OpenID consumer to find the server endpoint. However if this user
does not exist, never logged in or has hidden his profile that's the only thing that will
be shown - a blank page with some OpenID metadata for basic interop.

It's important to understand that a Profile record is a helper for metadata and not
something authoritative - it's the auth routine that takes the actual decision about the
user's state.

== Persistence

We store some data that the user might find useful to store and maybe display on his user
page. No sessions of the exchange are kept
except of the standard OpenID shared secrets (there are not linked to user records in any
way).

== SREG data sharing

There is currently no provision for fetching SREG data (like email, date of birth and such)
from the autorizing routine. We might consider this in the future, for now the user has to
fill it in himself.

== Sharding

The users in Pasaporte are segregated by the domain name of Pasaporte server. That is, if
you have two domains pointed at +one+ Pasaporte, you will not have name clashes between
the two domain names - the users are going to be split.