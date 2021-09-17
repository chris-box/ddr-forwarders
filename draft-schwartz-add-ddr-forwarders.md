---
title: "Discovery of Designated Resolvers in the Presence of Legacy Forwarders"
abbrev: "DDR and Forwarders"
docname: draft-schwartz-add-ddr-forwarders-latest
category: info

ipr: trust200902
area: General
workgroup: dprive
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: B. Schwartz
    name: Benjamin Schwartz
    organization: Google LLC
    email: bemasc@google.com

informative:
  FIREFOX-FALLBACK:
    target: https://support.mozilla.org/en-US/kb/firefox-dns-over-https#w_about-our-rollout-of-dns-over-https
    title: About our rollout of DNS over HTTPS
  MOZILLA-CANARY:
    target: https://support.mozilla.org/en-US/kb/canary-domain-use-application-dnsnet
    title: Canary domain - use-application-dns.net
  DUCK-CNAME:
    target: https://help.duckduckgo.com/duckduckgo-help-pages/features/safe-search/
    title: Force Safe Search at a Network Level
  BING-CNAME:
    target: https://help.bing.microsoft.com/#apex/bing/en-us/10003/0
    title: Block adult content with SafeSearch - Map at a network level
  GOOGLE-CNAME:
    target: https://support.google.com/websearch/answer/186669?hl=en
    title: Keep SafeSearch turned on for your school, workplace, or home network

--- abstract

This draft describes how the Discovery of Designated Resolvers (DDR) standard interacts with legacy DNS forwarders, including potential incompatibilities and relevant mitigations.

--- middle

# Conventions and Definitions

Legacy DNS Forwarder - An apparent DNS resolver, known to the client only by a non-public IP address, that forwards the client's queries to an upstream resolver, and has not been updated with any knowledge of DDR.

Cross-Forwarder Upgrade - Establishment of a direct, encrypted connection between the client and the upstream resolver.

# Introduction

## Background

The Discovery of Designated Resolvers specification {{?DDR=I-D.draft-ietf-add-ddr}} describes a mechanism for clients to learn about the encrypted protocols supported by a DNS server.  It also describes a conservative client validation policy that has strong security properties and is unlikely to create compatibility problems.

On the topic of client validation of encrypted DNS transports, the DDR specification says:

> If the IP address of a Designated Resolver differs from that of an Unencrypted Resolver, clients MUST validate that the IP address of the Unencrypted Resolver is covered by the SubjectAlternativeName of the Encrypted Resolver's TLS certificate

As TLS certificates cannot cover non-public IP addresses, this prevents clients that are behind a legacy DNS forwarder from connecting directly to the upstream resolver ("cross-forwarder upgrade").

Recent estimates suggest that a large fraction, perhaps a majority, of residential internet users in the United States and Europe rely on local DNS forwarders that are not compatible with DDR.

## Scope

This informational document describes the interaction between DDR and legacy DNS forwarders.  It discusses possible client policies, problems that might arise, and relevant mitigations.

DNS forwarders and resolvers that are implemented with awareness of DDR are out of scope, as they are not affected by this discussion (although see Security Considerations, {{security-considerations}}).

# Relaxed validation client policy {#client-policy}

We define a "relaxed validation" client policy as a client behavior that removes the certificate validation requirement when the Unencrypted Resolver is identified by a non-public IP address, regardless of the Designated Resolver's IP address.  This client policy is otherwise identical to the one described in {{DDR}}.

# Naturally compatible behaviors

The following network behaviors are naturally compatible with relaxed validation.

## Malware and threat domain filtering

Certain DNS forwarders block access to domains associated with malware and other threats.  Such threats rely on frequently changing domains, so these forwarders necessarily maintain an actively curated list of domains to block.  To ensure that this service is not lost due to a cross-forwarder upgrade, the maintainers can simply add "resolver.arpa" to the list.

This pattern has been deployed by Mozilla, with the domain "use-application-dns.net" {{MOZILLA-CANARY}}.

## Service category restrictions

Certain DNS forwarders may block access to domains based on the category of service provided by those domains, e.g. domains hosting services that are not appropriate for a work or school environment.  As in the previous section, this requires an actively curated list of domains, because the set of domains that offer a given type of service is constantly changing.  An actively managed blocking list can easily be revised to include "resolver.arpa".

## Time of use restrictions

Certain networks may impose restrictions on the time or duration of use by certain users.  This behavior is necessarily implemented below the DNS layer, because DNS-based blocking would be ineffective due to stub resolver caching, so it is not affected by changes in the DNS resolver.

# Privacy Considerations

The conservative validation policy results in no encryption when a legacy DNS forwarder is present.  This leaves the user's query activity vulnerable to passive monitoring {{?RFC7258}}, either on the local network or between the user and the upstream resolver.

The relaxed validation policy allows the use of encrypted transport in these configurations, reducing exposure to a passive surveillance adversary.

# Security Considerations {#security-considerations}

The relaxed validation procedure ({{client-policy}}) offers similar security properties to the stricter validation described in {{DDR}}, when a DDR-enabled resolver is identified by a non-public IP address.  With either policy, the client can establish a secure connection to the resolver in the absence of an active attacker, but an on-path attacker can impersonate the resolver and intercept all queries.  However, there are some important differences in the security properties that result from these policies.

## Transient attackers

With the conservative validation policy, a transient on-path attacker can only intercept queries for the duration of their active presence on the network.

With the relaxed validation behavior, a transient on-path attacker could implant a long-lived DDR response in the client's cache, directing their queries to the attacker's server long after the attacker has left the network.

### Solution: DNR

This attack does not apply if the client and network implement support for Discovery of Network-designated Resolvers {{?DNR=I-D.draft-ietf-add-dnr}}.

### Mitigation: Frequent refresh

The client can choose to refresh the DDR record arbitrarily frequently, e.g. by limiting the TTL.  For example, by limiting the TTL to 5 minutes, a client could ensure that any attacker can continue to monitor queries for at most 5 minutes after they have left the local network.

### Mitigation: Resolver reputation

A relaxed-validation client might choose to accept a potential cross-forwarder upgrade only if the designated encrypted resolver has sufficient reputation, according to some proprietary reputation scheme (e.g. a locally stored list of respectable resolvers).  This limits the ability of a DDR forgery attack to cause harm.

## Forensic logging

### Network-layer logging

With the conservative validation policy, a random sample of IP packets is likely sufficient for manual retrospective detection of an active attack.

With the relaxed validation policy, forensic logs must capture a specific packet (the attacker’s DDR designation response) to enable retrospective detection.

#### Mitigation: Log all DDR responses

Network-layer forensic logs that are not integrated with the resolver can enable detection of these attacks by logging all DDR responses, or more generally all DNS responses.  This makes retrospective attack detection straightforward, as the attacker's DDR response will indicate an unexpected server.

### DNS-layer logging

DNS-layer forensic logging conducted by a legacy DNS forwarder would be lost in a cross-forwarder upgrade.

#### Solution: Respond for resolver.arpa

Forwarders that want to observe all queries from relaxed validation clients will have to synthesize their own response for resolver.arpa, either implementing DDR or disabling it.

# Compatibility Considerations

Using DDR with legacy DNS forwarders also raises several potential concerns related to loss of existing network services.

## Split-horizon namespaces

Some network resolvers contain additional names that are not resolvable in the global DNS.  If these local resolvers are also legacy DNS forwarders, a client that performs a cross-forwarder upgrade might lose access to these local names.

### Mitigation: NXDOMAIN Fallback

In "NXDOMAIN Fallback", the client repeats a query to the unencrypted resolver if the encrypted resolver returns NXDOMAIN.  This allows the resolution of local names, provided they do not collide with globally resolvable names.

This is similar to the fallback behavior currently deployed in Mozilla Firefox {{FIREFOX-FALLBACK}}.

NXDOMAIN Fallback results in slight changes to the security and privacy properties of encrypted DNS.  Queries for nonexistent names no longer have protection against a local passive adversary, and local names are revealed to the upstream resolver.

NXDOMAIN Fallback is only applicable when a legacy DNS forwarder might be present, i.e. the unencrypted resolver has a non-public IP address, and the encrypted resolver has a different IP address.  In the other DDR configurations, any local names are expected to resolve similarly on both resolvers.

## Interposable domains

An "interposable domain" is a domain whose owner deliberately allows resolvers to forge certain responses.  This arrangement is most common for search engines, which often support a configuration where resolvers forge a CNAME record to direct all clients to a child-appropriate instance of the search engine {{DUCK-CNAME}}{{BING-CNAME}}{{GOOGLE-CNAME}}.

Future deployments of interposable domains can instruct administrators to enable or disable DDR when adding the forged record, but forged records in legacy DNS forwarders could be lost due to a cross-forwarder upgrade.

### Mitigation: Exemption list

There are a small number of pre-existing interposable domains, largely of interest only to web browsers.  Clients can maintain a list of relevant interposable domains and resolve them only via the network's resolver.

## Caching

Some legacy DNS forwarders also provide a shared cache for all network users.  Cross-forwarder upgrades will bypass this cache, resulting in slower DNS resolution.

### Mitigation: Stub caches

Clients can compensate partially for the loss of shared caching by implementing local DNS caches.

--- back

# Acknowledgments
{:numbered="false"}

TODO
