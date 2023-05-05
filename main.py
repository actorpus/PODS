import discord
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm
import threading
import asyncio
from datetime import timedelta
import os


def encode_to_braille(data: bytes) -> str:
    new_data = ""

    for char in data:
        char += 10240  # unicode offset for
        new_data += chr(char)

    return new_data


def decode_from_braille(data: str) -> bytes:
    new_data = b""

    for char in data:
        char = ord(char)
        char -= 10240
        new_data += char.to_bytes(1, 'big')

    return new_data


def break_every_n(text, n):
    partial = []

    for part in range(0, len(text), n):
        partial.append(text[part:part + n])

    return "\n".join(partial)


class Conversation(threading.Thread):
    def __init__(self, channel: discord.DMChannel, user):
        super(Conversation, self).__init__()

        self._channel = channel
        self._user_client = user

        self._keypair = self._generate_key()

    def _generate_key(self):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        uid = pgpy.PGPUID.new(
            str(self._user_client.user),
            comment="enc by actorp.us#7755",
            email=str(self._user_client.user.id),
        )

        key.add_uid(
            uid,
            usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
            key_expiration=timedelta(minutes=15)
        )

        return key

    def _send_message(self, message_content):
        self._user_client.message_que.append(
            (self._channel, message_content)
        )

    def send_message(self, message):
        # encrypt it here

        self._send_message(message)

    def send_key(self):
        pub_key = self._keypair.pubkey.__bytes__()
        pub_key = encode_to_braille(pub_key)
        pub_key = break_every_n(pub_key, 48)

        self._send_message(f"""
```ml
TEMPORARY CONVERSATION KEY
``````{pub_key}``````yaml
sencrypord
```
""")


class Client(discord.Client):
    def __init__(self):
        super(Client, self).__init__()
        self.conversations = {}
        self.message_que = []

        # loop = asyncio.get_event_loop()
        # loop.create_task(self._update_messages())

    async def start_conversation(self, channel):
        conv = Conversation(channel, self)

        conv.send_key()
        conv.send_message("Connected successfully")

        self.conversations[channel.id] = conv

    async def _update_messages(self):
        await asyncio.sleep(1)

        if not self.message_que:
            return

        message_channel, message_content = self.message_que.pop(0)

        await message_channel.send(message_content)

        # print("sending", message_channel_id, message_content)

    async def end_conversation(self, channel_id):
        del self.conversations[channel_id]

    async def on_ready(self):
        print(f"loggin in as {self.user}")

        while True:
            await self._update_messages()

    async def on_message(self, message):
        # only respond to ourselves
        if message.author != self.user:
            return

        if message.content == '!!enc':
            await self.start_conversation(message.channel)


Client().run(os.environ["UserToken"])
