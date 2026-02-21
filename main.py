#!/usr/bin/env python3

# SkunkChat

import argparse, os # ...
from sys import argv

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

from src.skunknet import Crypto, SkunkChat

class QDMApplication( QApplication ):
	pass

class QDMMainWindow( QWidget ):
	def __init__( self ):
		super().__init__()

		self.setMaximumSize( 1280, 720 )

		self.rootLayout = QVBoxLayout()
		self.rootLayout.setContentsMargins( 0, 10, 0, 0 )
		self.rootLayout.setAlignment( Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter  )

		self.headerLabel = QLabel( "SkunkNet" )
		self.headerLabel.setFixedSize( 1280, 60 )
		self.headerLabel.setAlignment( Qt.AlignmentFlag.AlignCenter )
		self.headerLabel.setStyleSheet( "font-size: 40px; font-weight: bold; color: #000000; background-color: transparent;" )

		self.Inbox = QTextEdit()
		self.Inbox.setFixedHeight( 500 )
		self.Inbox.setText( "Messages are displayed here..." )
		self.Inbox.setEnabled( False )
		self.Inbox.setStyleSheet( "font-size: 16px; color: #000000;" )

		self.messageBox = QTextEdit()
		# self.messageBox.setFixedSize()

		self.sendBtn = QPushButton( "Send" )
		self.sendBtn.setFixedHeight( 40 )

		self.rootLayout.addWidget( self.headerLabel )
		self.rootLayout.addWidget( self.Inbox )
		self.rootLayout.addWidget( self.messageBox )
		self.rootLayout.addWidget( self.sendBtn )

		self.setLayout( self.rootLayout )
	
if __name__ == "__main__":
	# Skunk needs SUDO privileges to capture net packets!
	if not "SUDO_UID" in os.environ.keys():
		exit( "[ERROR] Run program in sudo." )

	# Configure qt to run properly in SUDO
	if not os.environ.get( "XDG_RUNTIME_DIR" ):
		os.environ["XDG_RUNTIME_DIR"] = "/run/user/{}".format( os.getuid() )

	crypto = Crypto()

	parser = argparse.ArgumentParser(
		description = "SkunkNet's CLI",
		usage = "",
		epilog = "SkunkNet"
	)

	parser.add_argument(
		"--iface",
		type = str,
		help = "The interface to communicate through.",
		required = False,
		default = "wlp9s0"
	)
	parser.add_argument(
		"--priv_key",
		type = str,
		help = "The private key path.",
		required = False
	)
	parser.add_argument(
		"--pub_key",
		type = str,
		help = "The public key path.",
		required = False
	)
	parser.add_argument(
		"--new_priv_key",
		type = str,
		help = "Generate a new private key.",
		required = False
	)
	parser.add_argument(
		"--new_pub_key",
		type = str,
		help = "Generate a public key.",
		required = False
	)

	args = parser.parse_args()

	if ( args.priv_key and args.pub_key ) and ( not args.new_priv_key and not args.new_pub_key ):
		PRIVATE_KEY = Crypto.loadPrivateKey( args.priv_key )
		PUBLIC_KEY = Crypto.loadPublicKey( args.pub_key )
	elif ( args.new_priv_key and args.new_pub_key ) and ( not args.priv_key and not args.pub_key ):
		crypto.generateKeys()

		PRIVATE_KEY = crypto.loadPrivateKey( args.new_priv_key )
		PUBLIC_KEY = crypto.loadPublicKey( args.new_pub_key )
	else:
		parser.error( "[-] Please supply a private-public key pair or generate a new one." )

	print ( f"[+] Started a SkunkNet session on '{args.iface}'." )

	# Test with a Hello World message!
	enc_msg = Crypto.encryptMessage( PRIVATE_KEY, PUBLIC_KEY, "Hello World!" )
	skunkChat = SkunkChat( iface = args.iface )
	skunkChat.broadcast( message = enc_msg, ghost_proto = True )

	app = QDMApplication( argv )
	mainWind = QDMMainWindow()
	mainWind.show()
	exit( app.exec() )
