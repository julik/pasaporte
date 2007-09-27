==Onde está seu pasaporte?

This is Pasaporte, a small identity server with a colored bar on top. It's in the style
of Crowd (but smaller). Will act as a mediator between OpenID and arbitary services where
users are distinguished by their nickname (login), their password and a domain name.

==The idea

Pasaporte brings OpenID to the traditional simplicity of

 is_a_villain = check_password(login, password, domain)

The only thing you WILL need to change is the AUTH constant. It should contain the proc
that, when called, will return true or false. Yes, it's that simple. All the negotiation
smorgasbord, profile editing, encryptodecryption and other electrabombastic niceties are
going to be taken care of.

Should the password become stale or should the authentication backend say that it no
longer has the user in question the authorization tokens are immediately revoked, and any
authorization requests will be denied.

As an example we provide a simple adapter with which you can easily shoehorn OpenID into
Microsoft Remote Web Workplace server. And don't even dare to tell me about LDAP. LDAP is
for sissies.

==Configuration

The adventurous among us can override the defaults (Pasaporte constants) by placing a
hash-formatted YAML file called "config.yml" in the pasaporte dir. And don't ask me what
a "hash-formatted YAML file" is, because if you do you are not adventurous.

==A word of warning

Considering the clear-text passwords issue, we strongly recommend running Pasaporte under
SSL and under SSL only. But of course this might be prohibitive especially if you cannot
be self-signed or don't have an extra IP at hand.

==Profiles

Pasaporte allows the user to have a simple passport page, which lists hist interests and
maybe even sports his picture (do NOT think of goatse). The page is provided only if the
user tells that he wants to.

==The all-id

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

==Persistence

We store some data that the user might find useful to store and maybe display on his user
page. No sites that the user authorizes are stored. No sessions of the exchange are kept
except of the standard OpenID shared secrets (there are not linked to user records in any
way).

==Sharding

The users in Pasaporte are segregated by the domain name of Pasaporte server. That is, if
you have two domains pointed at +one+ Pasaporte, you will not have name clashes between
the two domain names - the users are going to be split.