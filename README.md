# PODS
PODS, or Piss Of Discord Staff, adds a layer of end-to-end encryption between DM's.
It acts as an external client for discord and detects when either members of a DM send a specific message,
After performing a key exchange it pops up an external window for the encrypted communications.

I am aware SimpleDiscordCrypt exists and will end up being a lot more user-friendly. PODS will not modify
the users current installation of discord in any way, and will use the OpenPGP implementation of RSA, 
thus might be a better option for people with a larger risk model

PODS also does not store conversation keys for longer than necessary and deletes any remnant data
preventing conversation recovery.

Please note this project uses discord.py-self, this module break's discords TOS.
As long as you don't use it, or this project, in public discord severs and stick strictly to DM's 
there are no known instances of people getting banned for it.

## todo

- [ ] Make it work lol
- [ ] Detect when a message is too long and break it into multiple parts
- [ ] Add trusted master certificates and sign temporary certificates to prevent MIM attacks
- [ ] Group chats / multiple DM members
- [ ] multiple conversations in one client instance
- [ ] automatic key retransmission at key expiration
