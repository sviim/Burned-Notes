To summarize: practically any domain user can request a Service Granting Ticket for any service account that has an SPN. That ticket is encrypted with the service account's hash. The attacker takes it offline and cracks it, the weak point is the service account's password
## Quick Kerberos Recap
### AS = Authentication Service
The first component of the KDC. Its job is to verify the user's identity and issue the TGT. Messages:
```cpp
AS-REQ   → Authentication Service Request   (client requests TGT)
AS-REP   → Authentication Service Reply     (KDC returns TGT)
```
### TGS = Ticket Granting Service
The second component of the KDC. Its job is to issue Service Tickets to users who already have a TGT. Messages:
```cpp
TGS-REQ  → Ticket Granting Service Request  (client requests ST by presenting TGT)
TGS-REP  → Ticket Granting Service Reply    (KDC returns ST)
```
### AP = Application
The final exchange between client and service:
```cpp
AP-REQ   → Application Request   (client presents ST to the service)
AP-REP   → Application Reply     (service confirms authentication)
```
Full flow with all 6 messages:
```cpp
AS-REQ  →
         ← AS-REP    (you get a TGT)
TGS-REQ →
         ← TGS-REP   (you get a ST)
AP-REQ  →
         ← AP-REP    (authenticated)
```
## How the Service Ticket Works
The ST identifies **who YOU are** to the service, not the other way around. Inside the ST, the KDC includes:
```cpp
- Your identity (svim@burned.corp)
- Your privilege level
- Validity timestamp
- Session Key to encrypt the communication
```
All of that is encrypted with the service account's hash. When SQL Server decrypts the ST using its own password, it reads your identity from inside and knows who you are, not the other way around.
## Attack Flow
As attackers, we first enumerate accounts with an `SPN` across the entire `AD`. We use `GetUserSPNs.py` for this:

![](images/Pasted-image-20260609205008.png)

With this tool we can easily enumerate accounts with SPNs:

![](images/Pasted-image-20260609205144.png)

We request a `ST` for that service account using `-request-user`:

![](images/Pasted-image-20260609205246.png)

We save it and run it through hashcat with mode `13100` (Kerberos 5 TGS-REP etype 23):

![](images/Pasted-image-20260609205450.png)

If we're lucky, we'll be able to crack it.
## Notes
This is much harder to pull off in a real environment, strong service account passwords or properly configured SPNs will usually stop the attack. But understanding Kerberoasting is essential groundwork for understanding more advanced attacks built on top of it.

It is important to remember that, once we have a valid TGT, we can request a Service Ticket (TGS) for any Kerberos-enabled service registered with an SPN. As long as the request is valid and we possess a legitimate TGT, the KDC will typically issue the ticket. Whether we are actually authorized to access the service is determined by the service itself when the ticket is presented. This is the key concept behind Kerberoasting, since even a low-privileged domain user can request TGSs for service accounts and attempt to crack them offline.
