## Unconstrained Delegation
The oldest and most dangerous method. It is configured on the delegating service account:
```cpp
Web Server has the flag: "TrustedForDelegation = True"
```
When a user authenticates to the Web Server with Unconstrained Delegation, the KDC includes the user's full TGT inside the TGS it sends to the Web Server:
```cpp
User → KDC: "I want to access the Web Server"
KDC → User: here is your TGS for Web Server + your full TGT inside it
User → Web Server: here is my TGS
Web Server extracts the user's TGT and stores it in memory
Web Server can now impersonate the user toward ANY service
```
The problem: the Web Server stores the user's TGT in memory. If we compromise the Web Server, we steal the TGTs of every user who connected, including `DC$`.
```cpp
Abuse: Coerce DC$ toward a server with Unconstrained Delegation
       → DC$ authenticates → its TGT lands in memory → DCSync
```
- During a standard TGS-REQ, the KDC only issues a service ticket for the requested SPN. The user's TGT is not part of the issued TGS. The exception is Unconstrained Delegation, where the KDC includes the user's forwarded TGT inside the service ticket delivered to the delegation-trusted server
## Constrained Delegation
Microsoft realized Unconstrained Delegation was too dangerous and introduced Constrained Delegation. Now the administrator explicitly defines which services can be delegated to:
```cpp
Web Server has:
msDS-AllowedToDelegateTo = [cifs/BBDD.corp, http/BBDD.corp]
```
The Web Server can only impersonate users toward those specific services, not just any. 

This is where S4U2Self and S4U2Proxy come in for the first time.
- The problem: only Domain Admins can configure this attribute, and it is set on the delegating account, not the receiving one
```cpp
WEB01$
msDS-AllowedToDelegateTo:
    MSSQLSvc/DB01.burned.corp
    cifs/FILE01.burned.corp
```
This means `WEB01$` can ask the KDC for tickets toward:
```cpp
MSSQLSvc/DB01.burned.corp
cifs/FILE01.burned.corp
```
Impersonating another user (via S4U), but not toward:
```cpp
ldap/DC01.burned.corp
cifs/DC01.burned.corp
http/CA01.burned.corp
```
Because those SPNs are not authorized
## T2A4D - TRUSTED_TO_AUTH_FOR_DELEGATION
T2A4D is a flag inside the `userAccountControl` attribute of an Active Directory object

`userAccountControl` is a numeric field that accumulates several flags via bitwise OR, things like "the account is disabled", "no password required", "trusted for delegation", etc. `T2A4D` is one of those flags:
```cpp
TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
```
When that bit is set on an account, the KDC knows that account has permission to perform `Protocol Transition`, meaning it can receive an authentication via any protocol (NTLM, a web form, whatever) and "convert" it to Kerberos by fabricating a TGS on its own via S4U2Self, without the user ever touching Kerberos.

In the Active Directory UI, that flag is activated when you select:
```cpp
Trust this computer for delegation to specified services only
    → Use any authentication protocol     ← here
```
And on the object it looks like this:
```cpp
userAccountControl: 0x1080000
                      ↑
                    among other bits, this includes TRUSTED_TO_AUTH_FOR_DELEGATION
```
That is all `T2A4D` is, a bit in `userAccountControl`. What makes it interesting is what the KDC decides based on it, if it is set, the tickets produced by S4U2Self come out `FORWARDABLE`, if it is not, they come out `non-forwardable`, and that is where classic Constrained Delegation breaks, but not `RBCD`
## Resource-Based Constrained Delegation (RBCD)
Introduced in Windows Server 2012. The fundamental change is where it is configured:
```cpp
Constrained:  configured on the DELEGATING account (requires DA to modify)
RBCD:         configured on the RECEIVING account (the resource owner decides who can delegate to it)

DAN-MACHINE$ has:
msDS-AllowedToActOnBehalfOfOtherIdentity = [EVIL$]
```
This means `DAN-MACHINE$` decides that `EVIL$` can impersonate users toward it. Any account with write permissions over `DAN-MACHINE$` can modify that attribute, including `DAN-MACHINE$` itself

### Why RBCD Bypasses T2A4D
RBCD changes who makes the trust decision. Instead of asking "does the delegating account have `T2A4D`?", the KDC asks "is this account listed in the `msDS-AllowedToActOnBehalfOfOtherIdentity` of the target?":
```cpp
S4U2Proxy in RBCD:
    KDC checks → Is EVIL$ in DAN-MACHINE$'s msDS-?
        → YES → ACCEPTED, even if the ticket is non-forwardable
```
## S4U2Self - Service for User to Self
Allows a service account to obtain a TGS on behalf of any user toward itself, without that user doing anything or even being present.
### Why does it exist?
For the case where a user authenticates to a service via NTLM (not Kerberos), but that service needs a Kerberos ticket to delegate to another service on the user's behalf:
```cpp
User authenticates to Web Server via NTLM
Web Server needs to access the DB via Kerberos on behalf of the user
Problem: it has no Kerberos TGS from the user because they authenticated via NTLM
Solution: S4U2Self — the Web Server asks the KDC for a TGS "as if" the user had authenticated via Kerberos
```
Flow:
```cpp
EVIL$  →  KDC: "Give me a TGS for Administrator toward myself (EVIL$)"
           [signed with EVIL$'s TGT]

KDC checks: does EVIL$ have S4U2Self permission? → Yes (any service account does)
KDC  →  EVIL$: here is your TGS [Administrator → EVIL$]
```
The result is a TGS that says:
- Administrator wants to access the service `EVIL$`

But this TGS only serves as evidence for the next step. It is only useful for `S4U2Proxy`.
## S4U2Proxy - Service for User to Proxy
Takes the TGS obtained via S4U2Self and uses it as evidence to request a TGS toward another service, impersonating the user:
```cpp
EVIL$  →  KDC: "I want a TGS to access cifs/DAN-MACHINE$ as Administrator"
           [presents the S4U2Self TGS as proof]

KDC verifies TWO things:
  1. Is the S4U2Self TGS valid? → Yes
  2. Is EVIL$ listed in DAN-MACHINE$'s msDS-AllowedToActOnBehalfOfOtherIdentity? → Yes (we put it there via relay)

KDC  →  EVIL$: here is your TGS [Administrator → cifs/DAN-MACHINE$]
```
## Full Attack Flow
```cpp
[Phase 1 - Relay]
DAN-MACHINE$ coerced → ntlmrelayx → LDAP on DC
ntlmrelayx writes to DAN-MACHINE$'s msDS-: "EVIL$ can delegate toward me"
ntlmrelayx creates EVIL$ with a password we control

[Phase 2 - S4U2Self]
EVIL$ → KDC: "Give me a TGS for Administrator toward myself"
KDC → EVIL$: TGS [Administrator → EVIL$]

[Phase 3 - S4U2Proxy]
EVIL$ → KDC: "I want to access DAN-MACHINE$ as Administrator"
              [presents the S4U2Self TGS]
KDC checks DAN-MACHINE$'s msDS- → EVIL$ is in the list → OK
KDC → EVIL$: TGS [Administrator → cifs/DAN-MACHINE$]

[Phase 4 - Access]
EVIL$ uses that TGS → psexec as Administrator on DAN-MACHINE$
```

> For a practical example using S4U2Self & S4U2Proxy, see: [](../coercion-NTLMRelay/Coercion-NTLMRelay.md)
