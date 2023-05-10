import discord
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags
import threading
import asyncio
from datetime import timedelta
import os
import random
import curses
from curses import textpad
import time


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


class Renderer(threading.Thread):
    def __init__(self):
        super(Renderer, self).__init__()

        self.conversations = []
        self.current_conversation = -1

        self.window_running = True
        self.entry_field = ""
        self.entry_pointer = 0

    def run(self) -> None:
        curses.wrapper(self.main)

    def main(self, stdscr: curses.window):
        stdscr.timeout(100)  # times out the getch to 100ms

        while self.window_running:
            key = stdscr.getch()

            # Esc
            if key == 27:
                self.window_running = False

            # ASCII printable characters
            elif 32 <= key <= 126:
                self.entry_field = self.entry_field[:self.entry_pointer] + chr(key) + self.entry_field[self.entry_pointer:]
                self.entry_pointer += 1

            # backspace
            elif key == 8 and self.entry_pointer > 0:
                self.entry_field = self.entry_field[:self.entry_pointer - 1] + self.entry_field[self.entry_pointer:]
                self.entry_pointer -= 1

            # delete
            elif key == 330 and self.entry_pointer < len(self.entry_field):
                self.entry_field = self.entry_field[:self.entry_pointer] + self.entry_field[self.entry_pointer + 1:]

            # left arrow
            elif key == 260:
                self.entry_pointer -= 1

                if self.entry_pointer == -1:
                    self.entry_pointer = len(self.entry_field)

            # right arrow
            elif key == 261:
                self.entry_pointer += 1

                if self.entry_pointer > len(self.entry_field):
                    self.entry_pointer = 0

            # entry key
            elif key == 10 and self.entry_field:
                self._send_message(self.entry_field)
                self.entry_field = ""
                self.entry_pointer = 0

            elif key > 0:
                print("unknown key", key)

            screen_size = stdscr.getmaxyx()
            stdscr.clear()
            textpad.rectangle(stdscr, 1, 2, screen_size[0] - 2, screen_size[1] - 3)
            stdscr.addstr(0, (screen_size[1] // 2) - 5, "sencrypord")

            if self.current_conversation == -1:
                stdscr.addstr(screen_size[0] // 2, (screen_size[1] // 2) - 8, "No Conversations")
                continue

            message_space = screen_size[0] - 3

            if message_space <= 0:
                stdscr.addstr(screen_size[0] // 2, (screen_size[1] // 2) - 10, "Please resize window")
                continue

            for i, (author, message, time_sent) in enumerate(list(reversed(self._get_messages()))[:message_space - 2]):
                t = time.strftime("%H:%M", time.localtime(time_sent))
                stdscr.addstr(message_space - i - 1, 3, f"{t:5s} {author:>26s} │ {message}")

            stdscr.addstr(message_space, 36, "╞>")
            stdscr.addstr(1, 36, "┬")
            stdscr.addstr(message_space + 1, 36, "┴")
            stdscr.addstr(message_space, 38, self.entry_field)

            stdscr.move(message_space, 38 + self.entry_pointer)

    def add_conversation(self, conversation):
        self.conversations.append(conversation)
        self.current_conversation += 1

    def _send_message(self, message: str) -> None:
        self.conversations[self.current_conversation].send_message(message)

    def _get_messages(self) -> list[tuple[str, str, int]]:
        return self.conversations[self.current_conversation].messages


class Conversation:
    def __init__(self, channel: discord.DMChannel, user):
        # super(Conversation, self).__init__()

        self._channel = channel
        self._user_client = user
        self._companion = ""

        self._keypair = self._generate_key()
        self._partner_pubkey: pgpy.PGPKey | None = None

        self.messages = []

    # def run(self) -> None:
    #     while True:
    #         inp = input()
    #         self.send_message(inp)

    def bind_partner(self, message):
        self._companion = str(message.author)

        message = message.content \
            .replace("```ml\nTEMPORARY CONVERSATION KEY\n``````", "") \
            .replace("``````yaml\nsencrypord\n```", "") \
            .replace("\n", "")

        key = decode_from_braille(message)
        key, _ = pgpy.PGPKey.from_blob(key)
        self._partner_pubkey = key

        self.send_message("Key received!")

    def parse_message(self, message):
        message = message.replace("\n", "")
        message = decode_from_braille(message)
        message = pgpy.PGPMessage.from_blob(message)
        message = self._keypair.decrypt(message)
        message = str(message.message)

        self.messages.append((self._companion, message, int(time.time())))

    def _generate_key(self):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        uid = pgpy.PGPUID.new(
            str(self._user_client.user),
            comment="sencrypord | actorp.us#7755",
            email=str(self._user_client.user.id) + "@user.discord.com",
            # possible automated email system on custom domain to process email to discord
        )

        key.add_uid(
            uid,
            usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
            key_expiration=timedelta(minutes=15)
        )

        return key

    def _send_message(self, message_content):
        return self._user_client.message_que.append(
            (self._channel, message_content)
        )

    def send_message(self, message):
        if self._partner_pubkey is None:
            print("Failed to send message, no pubkey was found")
            return

        self.messages.append((str(self._user_client.user), message, int(time.time())))

        message_id = random.randbytes(8).hex().upper()

        message = pgpy.PGPMessage.new(message)
        message = self._partner_pubkey.encrypt(message)
        message = message.__bytes__()
        message = encode_to_braille(message)

        if len(message) < 1000:
            message = break_every_n(message, 48)
            return self._send_message(f"```ml\n"
                                      # message number, total parts, message id
                                      f"MESSAGE 1 1 ID{message_id}\n"
                                      f"``````{message}``````yaml\n"
                                      f"sencrypord\n"
                                      f"```")
        message_parts = [
            message[i: i + 1000]
            for i in range(0, len(message), 1000)
        ]

        for i, part in enumerate(message_parts):
            part = break_every_n(part, 48)
            return self._send_message(f"```ml\n"
                                      f"MESSAGE {i} {len(message_parts)} ID{message_id}\n"
                                      f"``````{part}``````yaml\n"
                                      f"sencrypord\n"
                                      f"```")

    def send_key(self):
        pub_key = self._keypair.pubkey.__bytes__()
        pub_key = encode_to_braille(pub_key)
        pub_key = break_every_n(pub_key, 48)

        self._send_message(f"```ml\n"
                           f"TEMPORARY CONVERSATION KEY\n"
                           f"``````{pub_key}``````yaml\n"
                           f"sencrypord\n"
                           f"```")


class Client(discord.Client):
    def __init__(self):
        super(Client, self).__init__()
        self.conversations = {}
        self.message_que = []
        self.message_parts = {}

        self.renderer: None | Renderer = None

    async def start_conversation(self, channel):
        conv = Conversation(channel, self)

        conv.send_key()
        conv.send_message("Connected successfully")

        # conv.start()

        self.renderer.add_conversation(conv)
        self.conversations[channel.id] = conv

    async def _update_messages(self):
        await asyncio.sleep(1)

        if not self.message_que:
            return

        message_channel, message_content = self.message_que.pop(0)

        await message_channel.send(message_content)

    async def end_conversation(self, channel_id):
        del self.conversations[channel_id]

    async def on_ready(self):
        print(f"logging in as {self.user}, waiting for conversations")

        self.renderer = Renderer()
        self.renderer.start()

        while True:
            await self._update_messages()

    async def connection_request(self, message):
        if message.channel.id in self.conversations:
            self.conversations[message.channel.id].bind_partner(message)
            return

        print("No conversation for", message.author, "found, creating one now.")
        await self.start_conversation(message.channel)
        self.conversations[message.channel.id].bind_partner(message)

    async def parse_message(self, disc_message):
        if disc_message.channel.id not in self.conversations:
            return

        message_number, message = disc_message.content \
            .replace("```ml\nMESSAGE ", "", 1) \
            .split(" ", 1)
        message_number = int(message_number)

        total_parts, message = message.split(" ", 1)
        total_parts = int(total_parts)

        message_id, message = message.split("\n", 1)
        message_id = message_id[2:]

        message = message \
            .replace("``````", "", 1) \
            .replace("``````yaml\nsencrypord\n```", "", 1)

        if message_id in self.message_parts:
            self.message_parts[message_id][message_number] = message

        else:
            self.message_parts[message_id] = {
                message_number: message
            }

        if len(self.message_parts[message_id]) == total_parts:
            self.conversations[disc_message.channel.id].parse_message(
                "".join(self.message_parts[message_id].values())
            )

            del self.message_parts[message_id]

    async def on_message(self, message: discord.Message):
        # only respond to DM's
        if not isinstance(message.channel, discord.channel.DMChannel):
            return

        if message.author == self.user and message.content == '!!enc':
            await message.delete()
            await self.start_conversation(message.channel)
            return

        if message.author == self.user:
            return

        if not message.content.endswith("```yaml\nsencrypord\n```"):
            return

        if message.content.startswith("```ml\nTEMPORARY CONVERSATION KEY\n```"):
            await self.connection_request(message)
            return

        if message.content.startswith("```ml\nMESSAGE"):
            await self.parse_message(message)
            return


if __name__ == '__main__':
    try:
        token = os.environ["UserToken"]
    except KeyError:
        print("UserToken not found in environment variables")
        token = input("Enter token now > ")

    Client().run(token)
