## NTLM Authentication

Before diving into the attack, we need to understand how NTLM authentication works:

```c
Cliente                    Servidor
  |                           |
  |---(1) NEGOTIATE---------->|
  |                           |
  |<---(2) CHALLENGE----------|
  |      (nonce random)       |
  |                           |
  |---(3) AUTHENTICATE------->|
  |   (hash del challenge)    |
  |                           |
  |<---(4) ACCESS GRANTED-----|
```

The client sends a `NEGOTIATE` message to the server to agree on the authentication version (`NTLMv1` / `NTLMv2`). The server responds with a `CHALLENGE` (a random nonce), and the client must encrypt that challenge using its **NT Hash**. The operation looks like this:

```c
hash   = MD4(Client_Password)
result = HMAC-MD5(hash, server_challenge + client_challenge + timestamp + ...)
```

This cryptographic result is called `NTLMv2`, and it is what attackers attempt to crack during `LLMNR / NBT-NS` poisoning attacks using tools like `Responder`.

> **Key insight:** NTLM does not use a secure channel to verify identity. The server never directly validates the password — it only checks that the client was able to correctly encrypt the challenge. That is exactly what makes it exploitable.

---

## LLMNR / NBT-NS

In Active Directory environments, these attacks are extremely common. `LLMNR` (Link-Local Multicast Name Resolution) is a protocol that allows a client to resolve a hostname without a DNS server in the middle.

Imagine this: a user wants to access `\\FILESERVER\IMAGES` but mistypes it as `\\FILSERVER\IMAGES`. The system tries to resolve the name through DNS first — but it doesn't exist. At that point, it falls back to broadcast protocols:

- **LLMNR**
- **NBT-NS**

These protocols essentially broadcast to the entire local network: *"Does anyone know who FILSERVER is?"* — and that's where the attacker steps in.

**Normal flow (no attacker):**

```c
Client
   |
   |--- DNS Query ---> DNS Server
   |         Not found
   |
   |--- LLMNR Broadcast: "Who is FILSERVER?"
   |         No response
   |
   |--- NBT-NS Broadcast (second fallback)
   |         No response
   |
   |--- Error
```

**Attack flow:**

```c
Victim
   |
   |--- DNS Query
   |         Not found
   |
   |--- LLMNR Broadcast: "Who is FILESYSTEM?"
   |
Attacker listens and responds: "I am FILESYSTEM"
   |
   |--- Normal NTLM authentication begins
   |--- AUTHENTICATE message captured
```

Once the victim tries to authenticate, the attacker captures the `AUTHENTICATE` message, which contains:

- Username
- Domain
- Challenge
- NTLM Response

With this, the attacker can either **crack it offline** or use it in an **NTLM Relay attack**.

---

## Lab

Let's set up a simple lab to see how easy this is in practice. We are on the same local network, so `Ligolo-NG` or `Chisel` are not needed — but in a real engagement where you are pivoting, you would use them to route traffic through the correct interface.

First, verify connectivity to the DC:

![Ping to DC](images/01-ping-dc.png)

Check the network interface and start Responder:

![Responder start](images/02-responder-start.png)

The interface used here is `ens33`. Make sure to use your own interface name.

Now, from the victim machine, attempt to access a non-existent network resource in File Explorer:

![Victim File Explorer](images/03-victim-fileexplorer.png)

Windows will attempt to authenticate automatically. The victim sees a credentials prompt — this triggers the NTLM handshake:

![Credentials prompt](images/05-victim-credentials-prompt.png)

Meanwhile, Responder captures the `NTLMv2` hash of the `Administrator` account:

![Responder captures Administrator hash](images/04-responder-admin-hash.png)

The victim receives an `Access is denied` error — from their perspective, the resource simply doesn't exist:

![Access denied](images/06-victim-access-denied.png)

The same attack works against any domain user. Here, the `s.vim` account triggers the same flow and its hash is captured as well:

![Responder captures s.vim hash](images/07-responder-svim-hash.png)

Now we attempt to crack the captured hash offline using `Hashcat` with module `5600` (NetNTLMv2):

```c
hashcat -m 5600 hashNTLMv2 /usr/share/seclists/rockyou.txt
```

![Hashcat running](images/08-hashcat-start.png)

![Hashcat cracked](images/09-hashcat-cracked.png)

The password `snake123` was cracked in under **1 second** using `rockyou.txt`. This illustrates why weak passwords in domain environments are critical vulnerabilities — even if every other control is in place, a weak password makes the captured hash trivially exploitable.

> **Note:** NBT-NS and MDNS poisoning work in essentially the same way as LLMNR. What gets captured is identical — the specific protocol triggered depends on the environment and Windows version.

---

## Mitigations

### Disable LLMNR (Most effective)

Via Group Policy:

```c
Computer Configuration
→ Administrative Templates
→ Network → DNS Client
→ "Turn off multicast name resolution" → Enabled
```

### Disable NBT-NS

Per network adapter:

```c
Network Adapter Properties
→ IPv4 → Advanced → WINS
→ "Disable NetBIOS over TCP/IP"
```

This can also be pushed via DHCP option 001 if your DHCP server supports it.

### Network Segmentation

If users are isolated in separate VLANs, broadcast traffic does not reach the attacker. No broadcast, no poisoning.

### Strong Password Policy

Disabling LLMNR/NBT-NS **eliminates the attack vector entirely**. Strong passwords are a **secondary control** — they do not prevent hash capture, they only make offline cracking harder. A 15+ character password makes rockyou.txt and similar wordlists useless, but the hash is still captured and could be relayed.

### Detection

Monitor for anomalous LLMNR/NBT-NS responses on the network. Tools like **Microsoft Defender for Identity** or **Zeek** can alert on this behavior in production environments.
