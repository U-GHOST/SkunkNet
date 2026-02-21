# SkunkNet
* A secure, encrypted messaging protocol for intranets. It is a simple messaging "protocol" that uses the UDP protocol to send encrypted messages between devices inside the same network.
* **SkunkNet** is designed as a multicast protocol that sends data from the host machine to everyone in the network, expecting it to be received by another session of **SkunkChat**, decrypted, and displayed to the user.

* The end-goal to **SkunkNet** is just to really show how basic networking and encryption algorithms work.

---
## Messaging
* The **SkunkNet** protocol sends UDP packets from a source port `4753` to a destination port `3574`, with the identifiers `x` and `y`. The `x`-marked packets represent a signature signed by the private key, while the `y`-marked packets represent the actual message encrypted by the public key (which requires the private key and a valid signature to decrypt, constructing a working *Asymmetric* encryption algorithm ~ **C137**).
* Ideally, the "Chat Admin" will generate the private and public keys, sends it to the other users, and securely communicates with them.

* It's a pretty stupid concept but it has helped me deepen my understanding of networks and encryption algorithms, and hopefully it can help you too :smiley:.

---
## Getting Started
* **SkunkNet**'s cli requires the following arguments to render a **SkunkChat** window:
	* `--iface $IFACE`: The interface to communicate through.
	* `--priv_key $PATH`: The private key path.
	* `--pub_key $PATH`: The public key path.

* **SkunkChat** is the PyQt5-based GUI that is used for sending and receiving of the encrypted messages. No users, no databases, just pure, "structured chaos".

---
## Future Iterations
* In the near future, I'll re-write the `src.skunknet` as a Cython file, enforcing (semi) static types and building it as a C-lib/shared object (`.so`).
