#!/usr/bin/env python3

# SkunkNet Core

import os

# from datetime import datetime
from typing import (
	Optional,
	Tuple,
	Dict,
	Any,
)
from socket import gethostbyname, gethostname

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.volatile import RandMAC, RandIP
from scapy.packet import Raw
from scapy.sendrecv import sendp, send, sniff

# FIXME: Change the logic, pretty stupid!
class Crypto:
	"""
	Encryption/Decryption abstraction.
	"""
	
	def __init__(
		self,
		private_key: str,
		public_key: str
	):
		if not private_key.endswith( ".pem" ): self.private_key = private_key = private_key + ".pem"
		if not public_key.endswith( ".pem" ): self.public_key = public_key + ".pem"

	def generateKeys( self, skip_exists: Optional[bool] = False ):
		"""
		Generate a pair of private and public keys.

		:param skip_exists
		"""
		
		print ( "[+] Generating RSA private-public key pairs." )

		# It won't even bother checking for the public key
		if os.path.exists( self.private_key ) and not skip_exists: exit ( f"[-] Private key already exists in '{self.private_key}'. Exiting." )
		if os.path.exists( self.public_key ) and not skip_exists: exit ( f"[-] Public key already exists in '{self.public_key}'. Exiting." )

		# Generate the private and public keys
		private_key = rsa.generate_private_key( public_exponent = 65537, key_size = 2048 )
		public_key = private_key.public_key() # Extract it

		# Save the private key
		with open( f"{self.private_key}", "wb" ) as f:
			f.write(
				private_key.private_bytes(
					serialization.Encoding.PEM,
					serialization.PrivateFormat.PKCS8,
					serialization.NoEncryption()
				)
			)
		
		# Save public key
		with open( f"{self.public_key}", "wb" ) as f:
			f.write(
				public_key.public_bytes(
					serialization.Encoding.PEM,
					serialization.PublicFormat.SubjectPublicKeyInfo
				)
			)

		print ( f"[INFO] Generated RSA private-public key pairs." )

	@staticmethod
	def loadPrivateKey( private_key: str ) -> Any:
		"""
		Load a private key (both methods are scoped outside of the parent class, so they don't rely on the __init__ params).

		:param private_key
		"""

		with open( f"{private_key}", "rb" ) as f:
			return serialization.load_pem_private_key( f.read(), password = None )

	@staticmethod
	def loadPublicKey( public_key: str ) -> Any:
		"""
		Load a public key.

		:param public_key
		"""

		with open( f"{public_key}", "rb" ) as f:
			return serialization.load_pem_public_key( f.read() )
		
	def encryptMessage(
		self,
		private_key: loadPrivateKey,
		public_key: loadPublicKey,
		message: str
	) -> Dict[str, bytes]:
		"""
		Encrypt a message using the private-public keys.
		"""

		# Encrypt the message with the public key
		ciphertext = public_key.encrypt(
			message.encode(),
			padding.OAEP(
				mgf = padding.MGF1( hashes.SHA256() ),
				algorithm = hashes.SHA256(),
				label = None
			)
		)

		# Create a signature using the private key
		signature = private_key.sign(
			message.encode(),
			padding.PSS(
				mgf = padding.MGF1(hashes.SHA256() ),
				salt_length = padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)

		return {"ciphertext": ciphertext, "signature": signature}

	def decrypt_Message(
		self,
		private_key: loadPrivateKey,
		public_key: loadPublicKey,

		ciphertext: bytes,
		signature: bytes
	) -> Tuple[bool, str]:
		"""
		Decrypt a message using the private-public keys.
		"""

		plaintext = private_key.decrypt(
			ciphertext,
			padding.OAEP(
				mgf = padding.MGF1( algorithm = hashes.SHA256() ),
				algorithm = hashes.SHA256(),
				label = None
			)
		).decode()

		# Verify with public key
		try:
			public_key.verify(
				signature,
				plaintext.encode(),
				padding.PSS(
					mgf = padding.MGF1( hashes.SHA256() ),
					salt_length = padding.PSS.MAX_LENGTH
				),
				hashes.SHA256()
			)

			print ( "[INFO] Valid signature." )
		except Exception:
			print ( "[ERROR] Invalid signature." )

			return ( False, "" ) # FIXME: ...

		return ( True, plaintext )

# TODO: ...
class SkunkSec: # If we decide to make it more "secure", lol...
	pass

# TODO: Add an 'Export to .pcap' feature
class SkunkChat:
	"""
	...
	"""

	def __init__( self, iface: str ):
		self.iface: str = iface

	def __repr__( self ) -> str:
		return f""

	def broadcast(
		self,
		message: Any,

		ghost_proto: Optional[bool] = True
	) -> None:
		"""
		Broadcast a message accross the main interface.

		Args:
			message (Any): Ideally, the encrypted message (in bytes).
			ghost_proto (bool): Toggle ghost protocol for client anonymity.
		"""

		ADDR: str = gethostbyname( gethostname() )

		if ghost_proto:
			# Construct a signature packet
			signPacket = \
				Ether(
					src = RandMAC(),
					dst = "ff:ff:ff:ff:ff:ff"
				) / \
				IP(
					src = RandIP(),
					dst = RandIP()
				) / \
				UDP(
					sport = 4753,
					dport = 3574
				) / \
				Raw(
					load = f"x: {message['signature']}" # We're gonna construct the load as a string object
				)
			# Construct a message packet
			msgPacket = \
				Ether(
					src = RandMAC(),
					dst = "ff:ff:ff:ff:ff:ff"
				) / \
				IP(
					src = RandIP(),
					dst = RandIP()
				) / \
				UDP(
					sport = 4753,
					dport = 3574
				) / \
				Raw(
					load = f"y: {message['ciphertext']}"
				)
		else:
			# Ideally, both are "ghost protocol" methods (and the second is less sus tbh...)
			# TODO: Add a method that studies the network and mimics another device...
			signPacket = \
				Ether(
					src = RandMAC(), # MAC stays the same (for now)
					dst = "ff:ff:ff:ff:ff:ff"
				) / \
				IP(
					src = "192.168.1.1",
					dst = "192.168.1.1"
				) / \
				UDP(
					sport = 4753,
					dport = 3574
				) / \
				Raw(
					load = f"x: {message['signature']}"
				)
			msgPacket = \
				Ether(
					src = RandMAC(),
					dst = "ff:ff:ff:ff:ff:ff"
				) / \
				IP(
					src = "192.168.1.1",
					dst = "192.168.1.1"
				) / \
				UDP(
					sport = 4753,
					dport = 3574
				) / \
				Raw(
					load = f"y: {message['ciphertext']}"
				)

		sendp( signPacket, iface = self.iface, count = 1, verbose = 0 )
		sendp( msgPacket, iface = self.iface, count = 1, verbose = 0 )

	def receive( self ) -> None:
		"""
		Receive a message.

		Args:
			...
		"""

		# We can iterate with custom handlers to work with packet filters better...
		def handler( Packet ) -> None: pass

		sniff(
			prn = handler,
			filter = "",
			iface = self.iface,
			count = 0,
			store = False
		)

	def exportChat( self ) -> bool:
		"""
		'PCAP, or it didn't happen!'
		"""

		...
