import asyncio
import os
import sys
from pathlib import Path

from telethon import TelegramClient, errors
from telethon.sessions import StringSession


API_ID = 611335
API_HASH = "d524b414d21f4d37f08684c1df41ac9c"
SESSION_FILE = Path(__file__).resolve().parent / ".yzbot_session"

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")
MESSAGE_THREAD_ID = os.environ.get("MESSAGE_THREAD_ID")
COMMIT_URL = os.environ.get("COMMIT_URL")
COMMIT_MESSAGE = os.environ.get("COMMIT_MESSAGE")
RUN_URL = os.environ.get("RUN_URL")
TITLE = os.environ.get("TITLE")
VERSION = os.environ.get("VERSION")
BRANCH = os.environ.get("BRANCH")

MSG_TEMPLATE = """
**{title}**
Branch: {branch}
#ci_{version}
```
{commit_message}
```
[Commit]({commit_url})
[Workflow run]({run_url})
""".strip()


def get_caption():
    commit_url = COMMIT_URL or RUN_URL or ""
    commit_message = (COMMIT_MESSAGE or "").strip() or "(no message)"
    message = MSG_TEMPLATE.format(
        title=TITLE,
        branch=BRANCH,
        version=VERSION,
        commit_message=commit_message,
        commit_url=commit_url,
        run_url=RUN_URL,
    )
    if len(message) > 1024:
        return commit_url
    return message


def check_environ():
    global CHAT_ID, MESSAGE_THREAD_ID

    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN is not set")
    if not CHAT_ID:
        raise ValueError("CHAT_ID is not set")
    try:
        CHAT_ID = int(CHAT_ID)
    except ValueError:
        pass

    required = {
        "RUN_URL": RUN_URL,
        "TITLE": TITLE,
        "VERSION": VERSION,
        "BRANCH": BRANCH,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError(f"Missing environment variables: {', '.join(missing)}")

    if MESSAGE_THREAD_ID:
        try:
            MESSAGE_THREAD_ID = int(MESSAGE_THREAD_ID)
        except ValueError as error:
            raise ValueError("MESSAGE_THREAD_ID must be an integer") from error
    else:
        MESSAGE_THREAD_ID = None


def load_session():
    session_string = os.environ.get("SESSION_STRING", "").strip()
    if session_string:
        return StringSession(session_string), False

    if SESSION_FILE.exists():
        session_string = SESSION_FILE.read_text(encoding="utf-8").strip()
        if session_string:
            return StringSession(session_string), False

    return StringSession(""), True


def save_session(client):
    session_string = client.session.save()
    SESSION_FILE.write_text(session_string, encoding="utf-8")
    SESSION_FILE.chmod(0o600)
    print(f"[+] Session saved to {SESSION_FILE}")


async def main():
    check_environ()
    files = sys.argv[1:]
    if not files:
        raise ValueError("No files to upload")

    missing_files = [path for path in files if not Path(path).is_file()]
    if missing_files:
        raise FileNotFoundError(f"Missing upload files: {', '.join(missing_files)}")

    print("[+] Uploading to Telegram")
    print("[+] Files:", files)
    session, is_new = load_session()
    client = TelegramClient(session, API_ID, API_HASH)

    try:
        if is_new:
            print("[+] Logging in with a new bot session")
        else:
            print("[+] Using the configured bot session")
        await client.start(bot_token=BOT_TOKEN)
        if is_new:
            save_session(client)
    except errors.FloodWaitError as error:
        print(
            f"[-] Telegram requested a {error.seconds}-second flood wait; "
            "configure TELEGRAM_SESSION_STRING with a previously authorized session",
            file=sys.stderr,
        )
        raise

    try:
        captions = [""] * len(files)
        captions[-1] = get_caption()
        await client.send_file(
            entity=CHAT_ID,
            file=files,
            caption=captions,
            reply_to=MESSAGE_THREAD_ID,
            parse_mode="markdown",
        )
        print("[+] Upload complete")
    finally:
        await client.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as error:
        print(f"[-] Telegram upload failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
