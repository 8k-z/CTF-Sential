import asyncio
import json
import os
import random
import re
import secrets
import signal
import string
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

import discord
import requests
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ==============================================================================
# Configuration & Constants
# ==============================================================================

# Default configurations
DEFAULT_CONFIG = {
    "api_check_interval": 15,
    "notification_check_interval": 15,
    "notification_24h": True,
    "notification_1h": True,
    "auto_archive": True,
    "archive_delay": 60,  # minutes after CTF ends
    "admin_roles": []
}

DEFAULT_CTF_CREDENTIALS = {
    "user": "Not-Set",
    "pass": "random",
    "email": "Not-Set@gmail.com"
}

# Category names
CTF_CATEGORY_NAME = "🚩 Active CTFs"
ARCHIVE_CATEGORY_NAME = "📁 Archived CTFs"

# ==============================================================================
# Data Management Class
# ==============================================================================

class CTFDataManager:
    """Handles all persistent data for the CTF Sentinel Bot"""
    def __init__(self):
        self.ctf_cache = {}
        self.guild_configs = {}
        self.sent_notifications = {}
        self.guild_ctf_status = {}

    def save_all(self):
        """Save all data to their respective JSON files"""
        self.save_guild_configs()
        self.save_sent_notifications()
        self.save_guild_ctf_status()
        self.save_ctf_cache()
        log_message("💾 All persistent data saved")

    def load_all(self):
        """Load all data from JSON files"""
        self.load_guild_configs()
        self.load_sent_notifications()
        self.load_guild_ctf_status()
        self.load_ctf_cache()
        log_message("📂 All persistent data loaded")

    def save_guild_configs(self, filename='guild_configs.json'):
        serializable_configs = {str(gid): cfg for gid, cfg in self.guild_configs.items()}
        with open(filename, 'w') as f:
            json.dump(serializable_configs, f, indent=2)

    def load_guild_configs(self, filename='guild_configs.json'):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                loaded = json.load(f)
                self.guild_configs = {int(gid): cfg for gid, cfg in loaded.items()}

    def save_sent_notifications(self, filename='sent_notifications.json'):
        serializable_notifs = {str(gid): {k: list(v) for k, v in data.items()} 
                             for gid, data in self.sent_notifications.items()}
        with open(filename, 'w') as f:
            json.dump(serializable_notifs, f, indent=2)

    def load_sent_notifications(self, filename='sent_notifications.json'):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                loaded = json.load(f)
                self.sent_notifications = {int(gid): {k: set(v) for k, v in data.items()} 
                                        for gid, data in loaded.items()}

    def save_guild_ctf_status(self, filename='guild_ctf_status.json'):
        serializable_status = {str(gid): data for gid, data in self.guild_ctf_status.items()}
        with open(filename, 'w') as f:
            json.dump(serializable_status, f, indent=2)

    def load_guild_ctf_status(self, filename='guild_ctf_status.json'):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                loaded = json.load(f)
                self.guild_ctf_status = {int(gid): data for gid, data in loaded.items()}

    def save_ctf_cache(self, filename='ctf_cache.json'):
        try:
            with open(filename, 'w') as f:
                json.dump(self.ctf_cache, f, indent=2)
        except Exception as e:
            log_message(f"❌ Error saving ctf_cache: {e}")

    def load_ctf_cache(self, filename='ctf_cache.json'):
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    self.ctf_cache = json.load(f)
            except Exception as e:
                log_message(f"❌ Error loading ctf_cache: {e}")

# Global Data Manager instance
data_manager = CTFDataManager()
def generate_random_password(length=12, include_symbols=True):
    """Generate a random password with specified length and character set"""
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?" if include_symbols else ""
    
    # Ensure at least one character from each set
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits)
    ]
    
    if include_symbols:
        password.append(secrets.choice(symbols))
    
    # Fill the rest with random characters from all sets
    all_chars = lowercase + uppercase + digits + symbols
    for _ in range(length - len(password)):
        password.append(secrets.choice(all_chars))
    
    # Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def generate_ctf_friendly_password(length=10):
    """Generate a CTF-friendly password (alphanumeric only, easier to type)"""
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_memorable_password():
    """Generate a more memorable password using words and numbers"""
    adjectives = ["Swift", "Bold", "Cyber", "Elite", "Quick", "Smart", "Tech", "Code"]
    nouns = ["Hacker", "Ninja", "Warrior", "Master", "Expert", "Pro", "Team", "Squad"]
    
    adjective = secrets.choice(adjectives)
    noun = secrets.choice(nouns)
    number = secrets.randbelow(9999)
    
    return f"{adjective}{noun}{number:04d}"
# ==============================================================================
# Environment & Bot Setup
# ==============================================================================

BOT_TOKEN = os.getenv("BOT_TOKEN")  # Loaded from env file or environment variable

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# ==============================================================================
# Logging & Utility Functions
# ==============================================================================

def log_message(message: str):
    """Log with timestamp - enhanced for better debugging"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def parse_ctf_time_to_timestamp(time_str: str) -> Optional[int]:
    """Parse CTF time string and return Unix timestamp (UTC enforced)"""
    if not time_str:
        return None
    time_formats = ["%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", 
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]
    for fmt in time_formats:
        try:
            dt = datetime.strptime(time_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            continue
    try:
        dt = datetime.strptime(time_str[:19], "%Y-%m-%dT%H:%M:%S")
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None

def format_discord_timestamp(timestamp: int, style: str = "f") -> str:
    """Format Unix timestamp as Discord timestamp"""
    return f"<t:{timestamp}:{style}>"

def get_ctf_discord_timestamps(event: dict) -> dict:
    """Get Discord-formatted timestamps for a CTF event"""
    start_ts = parse_ctf_time_to_timestamp(event.get('start', ''))
    finish_ts = parse_ctf_time_to_timestamp(event.get('finish', ''))
    return {
        'start_timestamp': start_ts,
        'finish_timestamp': finish_ts,
        'start_discord': format_discord_timestamp(start_ts, 'F') if start_ts else "Unknown",
        'finish_discord': format_discord_timestamp(finish_ts, 'F') if finish_ts else "Unknown",
        'start_relative': format_discord_timestamp(start_ts, 'R') if start_ts else "Unknown",
        'finish_relative': format_discord_timestamp(finish_ts, 'R') if finish_ts else "Unknown"
    }

def sanitize_channel_name(name: str) -> str:
    """Convert CTF name to valid Discord channel name"""
    name = re.sub(r'[^a-zA-Z0-9\s\-_]', '', name)
    name = re.sub(r'\s+', '-', name.strip()).lower()
    if name and not name[0].isalnum():
        name = 'ctf-' + name
    return name[:100] if name else 'ctf-channel'

def extract_discord_link_from_description(event: dict) -> Optional[str]:
    """Extract Discord invite link from CTF description if available"""
    description = event.get('description', '')
    if not description: return None
    discord_patterns = [r'https://discord\.gg/[A-Za-z0-9]+', 
                        r'https://discord\.com/invite/[A-Za-z0-9]+',
                        r'discord\.gg/[A-Za-z0-9]+', 
                        r'discord\.com/invite/[A-Za-z0-9]+']
    for pattern in discord_patterns:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            url = match.group(0)
            return url if url.startswith('https://') else 'https://' + url
    return None

# ==============================================================================
# Helper Functions & Utilities
# ==============================================================================

def get_setup_guilds() -> List[int]:
    """Get list of guilds that have completed setup"""
    return [int(gid) for gid, cfg in data_manager.guild_configs.items() if cfg.get("setup_complete")]

def user_has_ctf_permissions(user: discord.Member, guild_id: int) -> bool:
    """Check if user has permission to manage CTFs"""
    if user.guild_permissions.administrator: return True
    admin_roles = get_guild_setting(guild_id, "admin_roles")
    if not admin_roles: return False
    return any(role.id in admin_roles for role in user.roles)

def get_ctf_id(event: dict) -> str:
    """Standardized ID generation for CTFs"""
    title = event.get('title', 'ctf')
    eid = event.get('id', 'unk')
    return f"{title}_{eid}"


def get_guild_notifications(guild_id: int) -> dict:
    """Get notification tracking for a specific guild"""
    if guild_id not in data_manager.sent_notifications:
        data_manager.sent_notifications[guild_id] = {
            '24h': set(),
            '1h': set(), 
            'channel_1h': set(),  # NEW: Track channel reminders
            'archived': set(),
        }
    return data_manager.sent_notifications[guild_id]

def has_notification_been_sent(guild_id: int, ctf_id: str, notification_type: str) -> bool:
    """Check if a notification has been sent for a specific guild"""
    guild_notifications = get_guild_notifications(guild_id)
    return ctf_id in guild_notifications[notification_type]

def mark_notification_sent(guild_id: int, ctf_id: str, notification_type: str):
    """Mark a notification as sent for a specific guild"""
    guild_notifications = get_guild_notifications(guild_id)
    guild_notifications[notification_type].add(ctf_id)

def get_guild_config(guild_id: int) -> dict:
    """Get guild configuration with default values"""
    if guild_id not in data_manager.guild_configs:
        data_manager.guild_configs[guild_id] = {
            "setup_complete": False,
            "channel_id": None,
            "settings": DEFAULT_CONFIG.copy(),
            "ctf_channels": {},
            "ctf_credentials": DEFAULT_CTF_CREDENTIALS.copy()
        }
    return data_manager.guild_configs[guild_id]

def is_guild_setup_complete(guild_id: int) -> bool:
    """Check if guild setup is complete"""
    return get_guild_config(guild_id).get("setup_complete", False)

def get_guild_channel_id(guild_id: int) -> Optional[int]:
    """Get configured channel ID for a guild"""
    if not is_guild_setup_complete(guild_id):
        return None
    return get_guild_config(guild_id).get("channel_id")

def set_guild_channel_id(guild_id: int, channel_id: int):
    """Set channel ID for a guild and mark setup as complete"""
    config = get_guild_config(guild_id)
    config["channel_id"] = channel_id
    config["setup_complete"] = True
    log_message(f"✅ Guild {guild_id} setup completed with channel {channel_id}")

def get_guild_setting(guild_id: int, setting: str):
    """Get a specific setting for a guild"""
    config = get_guild_config(guild_id)
    return config["settings"].get(setting, DEFAULT_CONFIG.get(setting))

def set_guild_setting(guild_id: int, setting: str, value):
    """Set a specific setting for a guild"""
    config = get_guild_config(guild_id)
    config["settings"][setting] = value
    log_message(f"🔧 Guild {guild_id} setting '{setting}' set to {value}")

def get_guild_credentials(guild_id: int) -> dict:
    """Get CTF credentials for a guild"""
    config = get_guild_config(guild_id)
    return config.get("ctf_credentials", DEFAULT_CTF_CREDENTIALS.copy())

def set_guild_credentials(guild_id: int, credentials: dict):
    """Set CTF credentials for a guild"""
    config = get_guild_config(guild_id)
    config["ctf_credentials"] = credentials
    log_message(f"🔧 Guild {guild_id} CTF credentials updated")

def register_ctf_channel(guild_id: int, ctf_id: str, channel_id: int):
    """Register a CTF channel for tracking"""
    config = get_guild_config(guild_id)
    config["ctf_channels"][ctf_id] = channel_id

def get_ctf_channel(guild_id: int, ctf_id: str) -> Optional[int]:
    """Get CTF channel ID"""
    config = get_guild_config(guild_id)
    return config["ctf_channels"].get(ctf_id)

# ==============================================================================
# Interaction Views
# ==============================================================================

class CTFActionButtons(discord.ui.View):
    def __init__(self, ctf_id: str):
        super().__init__(timeout=None)
        self.ctf_id = ctf_id
        
        # Set deterministic custom_ids for persistence
        self.join_ctf.custom_id = f"ctf:join:{ctf_id}"
        self.show_info.custom_id = f"ctf:info:{ctf_id}"
        self.skip_ctf.custom_id = f"ctf:skip:{ctf_id}"
    
    async def get_event_data(self):
        """Fetch event data from data manager cache"""
        return data_manager.ctf_cache.get(self.ctf_id)

    @discord.ui.button(label='Join CTF', style=discord.ButtonStyle.green, emoji='🚩')
    async def join_ctf(self, interaction: discord.Interaction, button: discord.ui.Button):
        event_data = await self.get_event_data()
        if not event_data:
            await interaction.response.send_message("❌ CTF data not found (expired or cleared).", ephemeral=True)
            return

        # Check permissions
        if not user_has_ctf_permissions(interaction.user, interaction.guild.id):
            await interaction.response.send_message("❌ You don't have permission to join CTFs.", ephemeral=True)
            return
        
        await interaction.response.defer(ephemeral=True)
        
        try:
            guild = interaction.guild
            category = await get_or_create_category(guild, CTF_CATEGORY_NAME)
            channel_name = sanitize_channel_name(event_data['title'])
            
            existing_channel = discord.utils.get(guild.text_channels, name=channel_name)
            if existing_channel:
                await interaction.followup.send(f"✅ CTF channel already exists: {existing_channel.mention}", ephemeral=True)
                mark_ctf_joined(guild.id, self.ctf_id)
                return
            
            # Create channel
            channel = await guild.create_text_channel(
                name=channel_name,
                category=category,
                topic=f"CTF: {event_data['title']} | {event_data.get('url', 'No URL')}"
            )
            
            # Register and update status
            get_guild_config(guild.id)["ctf_channels"][self.ctf_id] = channel.id
            mark_ctf_joined(guild.id, self.ctf_id)
            
            # Post credentials
            credentials = get_guild_config(guild.id).get("ctf_credentials", DEFAULT_CTF_CREDENTIALS)
            ctf_password = generate_random_password(12)
            ts = get_ctf_discord_timestamps(event_data)
            
            embed = discord.Embed(title=f"🚩 {event_data['title']} - Login Details", color=discord.Color.green())
            embed.description = (f"**Website:** {event_data.get('url', 'N/A')}\n"
                                f"**User:** `{credentials['user']}`\n"
                                f"**Pass:** `{ctf_password}`\n"
                                f"**Email:** `{credentials['email']}`")
            
            discord_link = extract_discord_link_from_description(event_data)
            if discord_link:
                embed.description += f"\n**Discord:** {discord_link}"
                
            embed.add_field(name="📅 Start", value=ts['start_relative'], inline=True)
            embed.add_field(name="🏁 End", value=ts['finish_relative'], inline=True)
            
            await channel.send(content="@everyone", embed=embed)
            await interaction.followup.send(f"✅ Created channel: {channel.mention}", ephemeral=True)
            log_message(f"✅ Channel #{channel.name} created for {event_data['title']}")
            
        except Exception as e:
            log_message(f"❌ Error in join_ctf: {e}")
            await interaction.followup.send(f"❌ Error creating channel: {str(e)}", ephemeral=True)

    @discord.ui.button(label='More Info', style=discord.ButtonStyle.primary, emoji='ℹ️')
    async def show_info(self, interaction: discord.Interaction, button: discord.ui.Button):
        event_data = await self.get_event_data()
        if not event_data:
            await interaction.response.send_message("❌ CTF data not found.", ephemeral=True)
            return

        ts = get_ctf_discord_timestamps(event_data)
        embed = discord.Embed(title=f"{event_data['title']} - Info", color=discord.Color.blue(), url=event_data.get('url', ''))
        embed.description = event_data.get('description', 'No description.')[:2000]
        embed.add_field(name="📅 Start", value=ts['start_discord'], inline=True)
        embed.add_field(name="🏁 End", value=ts['finish_discord'], inline=True)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @discord.ui.button(label='Skip', style=discord.ButtonStyle.secondary, emoji='⏭️')
    async def skip_ctf(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not user_has_ctf_permissions(interaction.user, interaction.guild.id):
            await interaction.response.send_message("❌ Admin permissions required.", ephemeral=True)
            return
        mark_ctf_skipped(interaction.guild.id, self.ctf_id)
        await interaction.response.send_message(f"✅ Permanently skipped **{self.ctf_id}**.", ephemeral=True)

async def get_or_create_category(guild: discord.Guild, category_name: str):
    """Utility to find or build a category"""
    category = discord.utils.get(guild.categories, name=category_name)
    if category: return category
    try:
        category = await guild.create_category_channel(category_name)
        log_message(f"✅ Created category: {category_name}")
        return category
    except Exception as e:
        log_message(f"❌ Category error: {e}")
        return None

def user_has_ctf_permissions(user: discord.Member, guild_id: int) -> bool:
    """Check if user has permission to manage CTFs"""
    if user.guild_permissions.administrator: return True
    admin_roles = get_guild_setting(guild_id, "admin_roles")
    if not admin_roles: return False
    return any(role.id in admin_roles for role in user.roles)

def get_ctf_id(event: dict) -> str:
    """Standardized ID generation for CTFs"""
    title = event.get('title', 'ctf')
    eid = event.get('id', 'unk')
    return f"{title}_{eid}"

# ==============================================================================
# Notification Utilities
# ==============================================================================

async def send_ctf_channel_reminder(guild_id: int, ctf_id: str, event: dict):
    """Send reminder directly to the dedicated CTF channel"""
    channel_id = get_guild_config(guild_id).get("ctf_channels", {}).get(ctf_id)
    if not channel_id: return False
    
    channel = bot.get_channel(channel_id)
    if not channel: return False
    
    ts = get_ctf_discord_timestamps(event)
    embed = discord.Embed(title="🚨 Reminder: CTF Starting Soon!", color=discord.Color.red())
    embed.description = f"**{event['title']}** starts {ts['start_relative']}!"
    
    await channel.send(content="@everyone", embed=embed)
    log_message(f"🚨 Sent channel reminder for {event['title']}")
    return True

# ==============================================================================
# CTF Logic & Background Tasks
# ==============================================================================

async def fetch_and_cache_ctfs():
    """Fetch upcoming CTFs from CTFTime and cache them"""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    start_time = int(datetime.now().timestamp())
    end_time = int((datetime.now() + timedelta(days=10)).timestamp())
    url = f"https://ctftime.org/api/v1/events/?limit=15&start={start_time}&finish={end_time}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            events = response.json()
            new_cache = {get_ctf_id(e): e for e in events}
            data_manager.ctf_cache = new_cache
            data_manager.save_ctf_cache()
            log_message(f"✅ Fetched {len(events)} CTFs from API")
            return True
    except Exception as e:
        log_message(f"❌ API fetch error: {e}")
    return False

async def check_notification_triggers():
    """Check and send notifications for all set up guilds"""
    now = datetime.now(timezone.utc)
    for gid in get_setup_guilds():
        guild = bot.get_guild(gid)
        if not guild: continue
        
        for cid, event in data_manager.ctf_cache.items():
            start_ts = parse_ctf_time_to_timestamp(event.get('start'))
            if not start_ts: continue
            
            start_dt = datetime.fromtimestamp(start_ts, timezone.utc)
            hours_until = (start_dt - now).total_seconds() / 3600
            
            if not should_send_notification(gid, cid):
                # If joined, check for 1h channel reminder
                if is_ctf_joined(gid, cid) and 0 < hours_until <= 1.5:
                    if not has_notification_been_sent(gid, cid, 'channel_1h'):
                        if await send_ctf_channel_reminder(gid, cid, event):
                            mark_notification_sent(gid, cid, 'channel_1h')
                continue
            
            # 24h notification
            if 23 <= hours_until <= 25 and get_guild_setting(gid, 'notification_24h'):
                if not has_notification_been_sent(gid, cid, '24h'):
                    await send_guild_notification(gid, cid, event, '24h')
            
            # 1h notification
            elif 0 < hours_until <= 1.5 and get_guild_setting(gid, 'notification_1h'):
                if not has_notification_been_sent(gid, cid, '1h'):
                    await send_guild_notification(gid, cid, event, '1h')

async def send_guild_notification(guild_id: int, ctf_id: str, event: dict, type: str):
    """Send CTF alert to the primary notification channel"""
    channel_id = get_guild_channel_id(guild_id)
    if not channel_id: return
    
    channel = bot.get_channel(channel_id)
    if not channel: return
    
    ts = get_ctf_discord_timestamps(event)
    color = discord.Color.orange() if type == '24h' else discord.Color.red()
    embed = discord.Embed(title=f"🚩 {event['title']}", color=color, url=event.get('url', ''))
    embed.description = f"**Starting {ts['start_relative']}**\n\n{event.get('description', '')[:300]}..."
    embed.add_field(name="📅 Start", value=ts['start_discord'], inline=True)
    embed.set_footer(text=f"CTF Sentinel • {type.upper()} Alert")
    
    await channel.send(embed=embed, view=CTFActionButtons(ctf_id))
    mark_notification_sent(guild_id, ctf_id, type)
    log_message(f"📡 Sent {type} notification for {event['title']} to {channel.name}")

@tasks.loop(minutes=15)
async def api_fetch_task():
    await fetch_and_cache_ctfs()

@tasks.loop(minutes=15)
async def notification_check_task():
    await check_notification_triggers()

@tasks.loop(minutes=30)
async def auto_save_task():
    data_manager.save_all()

@bot.event
async def on_ready():
    log_message(f"🤖 Bot logged in as {bot.user.name}")
    data_manager.load_all()
    
    # Restore persistent views
    for cid in data_manager.ctf_cache:
        bot.add_view(CTFActionButtons(cid))
    
    try:
        synced = await bot.tree.sync()
        log_message(f"✅ Synced {len(synced)} slash commands")
    except Exception as e:
        log_message(f"❌ Sync error: {e}")
    
    api_fetch_task.start()
    notification_check_task.start()
    auto_save_task.start()

@bot.event
async def on_guild_join(guild: discord.Guild):
    log_message(f"🆕 Joined guild: {guild.name}")
    # Welcome message can be added here if needed

# Graceful shutdown
async def shutdown():
    log_message("🛑 Saving data before shutdown...")
    data_manager.save_all()
    await bot.close()

def signal_handler(sig, frame):
    log_message(f"📡 Received signal {sig}")
    asyncio.create_task(shutdown())

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Slash Commands
# ==============================================================================
# Slash Commands
# ==============================================================================

@bot.tree.command(name="bot_setup", description="Initial setup for the server")
@app_commands.describe(channel="Notification channel")
@app_commands.default_permissions(administrator=True)
async def slash_setup_bot(interaction: discord.Interaction, channel: Optional[discord.TextChannel] = None):
    ch = channel or interaction.channel
    set_guild_channel_id(interaction.guild.id, ch.id)
    get_guild_config(interaction.guild.id)["setup_complete"] = True
    
    embed = discord.Embed(title="🚀 Setup Complete", color=discord.Color.green())
    embed.description = f"Notifications will be sent to {ch.mention}."
    await interaction.response.send_message(embed=embed)
    
    await fetch_and_cache_ctfs()
    await check_notification_triggers()

@bot.tree.command(name="team_details", description="Set team credentials")
@app_commands.default_permissions(administrator=True)
async def slash_team_details(interaction: discord.Interaction, user: str, email: str):
    set_guild_credentials(interaction.guild.id, {"user": user, "email": email, "pass": "random"})
    await interaction.response.send_message("✅ Team credentials updated.", ephemeral=True)

@bot.tree.command(name="bot_settings", description="Configure preferences")
@app_commands.default_permissions(administrator=True)
async def slash_bot_settings(interaction: discord.Interaction, 
                             n24h: Optional[bool] = None, n1h: Optional[bool] = None):
    gid = interaction.guild.id
    if n24h is not None: set_guild_setting(gid, "notification_24h", n24h)
    if n1h is not None: set_guild_setting(gid, "notification_1h", n1h)
    await interaction.response.send_message("✅ Settings updated.", ephemeral=True)

@bot.tree.command(name="ctf_reset_notifications", description="Clear notification history")
@app_commands.default_permissions(administrator=True)
async def slash_reset_notifications(interaction: discord.Interaction):
    gid = interaction.guild.id
    data_manager.sent_notifications[str(gid)] = {"24h": [], "1h": [], "channel_1h": [], "archived": []}
    await interaction.response.send_message("🔄 Notification history reset.", ephemeral=True)

@bot.tree.command(name="generate_password", description="Get a secure password")
async def slash_generate_password(interaction: discord.Interaction, length: int = 12):
    pw = generate_random_password(max(8, min(length, 50)))
    await interaction.response.send_message(f"🔐 Password: `{pw}`", ephemeral=True)

# ==============================================================================
# Execution Block
# ==============================================================================

if __name__ == "__main__":
    if not BOT_TOKEN:
        print("❌ Error: BOT_TOKEN not found in .env or environment")
        sys.exit(1)
        
    try:
        bot.run(BOT_TOKEN)
    except Exception as e:
        log_message(f"❌ Critical error: {e}")
