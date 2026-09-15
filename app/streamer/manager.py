from telethon import TelegramClient
from telethon.sessions import StringSession
from app.database.connection import settings
import logging

logger = logging.getLogger(__name__)

class SessionManager:
    def __init__(self):
        self.clients = []
        self.bot_client = None
        self._index = 0
        self._has_user_sessions = False

    async def start(self):
        from telethon.sessions import MemorySession
        # Start Bot Client
        self.bot_client = TelegramClient(MemorySession(), settings.API_ID, settings.API_HASH)
        await self.bot_client.start(bot_token=settings.BOT_TOKEN)
        logger.info("Bot client started")

        # Start User Clients (for high-speed streaming)
        session_strings = [s.strip() for s in settings.SESSIONS.split(",") if s.strip()]
        
        if not session_strings:
            logger.warning("No user sessions found! Using bot for streaming.")
            self.clients.append(self.bot_client)
        else:
            for i, session_str in enumerate(session_strings):
                try:
                    client = TelegramClient(
                        StringSession(session_str), 
                        settings.API_ID, 
                        settings.API_HASH,
                        connection_retries=5
                    )
                    await client.start()

                    # Telethon can only resolve a channel by ID if that channel is
                    # in the account's entity cache. Without this, every request
                    # from a user session fails with "no access to file" /
                    # ChannelInvalidError even though the account is a member.
                    try:
                        await client.get_dialogs(limit=500)
                    except Exception as e:
                        logger.warning(f"Session {i+1}: could not preload dialogs: {e}")

                    if settings.CHANNEL_ID:
                        try:
                            await client.get_entity(settings.CHANNEL_ID)
                        except Exception as e:
                            logger.error(
                                f"Session {i+1} CANNOT access storage channel "
                                f"{settings.CHANNEL_ID}: {e}. This account must JOIN "
                                f"the storage channel or its links will fail."
                            )
                            await client.disconnect()
                            continue

                    self.clients.append(client)
                    self._has_user_sessions = True
                    logger.info(f"User Session {i+1} started")
                except Exception as e:
                    logger.error(f"Session {i+1} failed: {e}")
            
            if not self.clients:
                logger.warning("No usable user sessions. Falling back to the bot client.")
                self.clients.append(self.bot_client)

    async def stop(self):
        for client in self.clients:
            await client.disconnect()

    def has_user_sessions(self):
        """True when at least one real user account is streaming."""
        return self._has_user_sessions

    def get_client(self):
        if not self.clients:
            return self.bot_client
        client = self.clients[self._index]
        self._index = (self._index + 1) % len(self.clients)
        return client

    def get_all_clients(self):
        """Return all available clients for parallel downloading"""
        return self.clients if self.clients else [self.bot_client]

    async def resolve_media(self, chat_id: int, message_id: int):
        """
        Fetch the media message with EVERY client separately.

        A Telegram file reference is only valid for the account that fetched it.
        Reusing one account's reference across the other sessions is the second
        cause of "no access to file" errors, so each client gets its own.

        Returns a list of (client, media) pairs; empty if nobody can read it.
        """
        pairs = []
        for client in self.get_all_clients():
            try:
                msg = await client.get_messages(chat_id, ids=message_id)
                if not msg or not msg.media:
                    continue
                media = msg.media
                if hasattr(media, 'document'):
                    media = media.document
                elif hasattr(media, 'photo'):
                    media = media.photo
                pairs.append((client, media))
            except Exception as e:
                logger.warning(f"A session could not read message {message_id}: {e}")

        if not pairs and self.bot_client not in self.get_all_clients():
            try:
                msg = await self.bot_client.get_messages(chat_id, ids=message_id)
                if msg and msg.media:
                    media = msg.media
                    if hasattr(media, 'document'):
                        media = media.document
                    elif hasattr(media, 'photo'):
                        media = media.photo
                    pairs.append((self.bot_client, media))
                    logger.info("Fell back to the bot client for this file.")
            except Exception as e:
                logger.error(f"Bot fallback failed for message {message_id}: {e}")

        return pairs

session_manager = SessionManager()
