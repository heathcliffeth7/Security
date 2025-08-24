import discord
from discord.ext import commands
import os
from datetime import timedelta
import dotenv   # For .env file support
import re
import random
import string
import io
import asyncio
from collections import defaultdict
import json
import time
import signal
import threading
from pathlib import Path
_PIL_AVAILABLE = False
try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter
    _PIL_AVAILABLE = True
    print("[PIL] Successfully imported PIL modules")
except ImportError as e:
    print(f"[PIL] Import failed - ImportError: {e}")
except Exception as e:
    print(f"[PIL] Import failed - Other error: {e}")

print(f"[PIL] Final status: _PIL_AVAILABLE = {_PIL_AVAILABLE}")
try:
    import regex as _advanced_regex_engine  # third-party 'regex' module (if available)
    _REGEX_ENGINE = _advanced_regex_engine
    _REGEX_ENGINE_NAME = "regex"
except Exception:  # pragma: no cover
    _REGEX_ENGINE = re
    _REGEX_ENGINE_NAME = "re"

# Load environment variables from .env file
dotenv.load_dotenv()

# Debug mode configuration
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"
if DEBUG_MODE:
    print("🐛 DEBUG MODE ENABLED - Sensitive information may be logged!")
else:
    print("🔒 PRODUCTION MODE - Debug logging disabled")

# Intent settings
intents = discord.Intents.default()
intents.members = True  # Required for member join events
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# Global check: disable all commands in DMs (guild-only)
@bot.check
async def _block_dm_commands(ctx: commands.Context) -> bool:
    # Return False for DMs so commands are ignored
    return ctx.guild is not None

# Security Authorization
# Load security role ID from environment variable for better security
security_authorized_role_id = int(os.getenv("SECURITY_MANAGER_ROLE_ID", "0"))
if security_authorized_role_id == 0:
    print("⚠️  WARNING: SECURITY_MANAGER_ROLE_ID environment variable not set!")
    print("Security commands will only work with manually added IDs via !securityauthorizedadd")
    print("To set a default security role: export SECURITY_MANAGER_ROLE_ID='your_role_id_here'")

security_authorized_ids = set()

# Security limits and audit
MAX_SECURITY_AUTHORIZED_USERS = 4  # Maximum number of authorized users/roles
security_audit_log = []  # Store security actions for audit

# Rate limiting for critical operations
command_rate_limits = defaultdict(list)  # user_id -> [timestamp, timestamp, ...]
SECURITY_COMMAND_RATE_LIMIT = 5  # Max 5 security commands per minute
SECURITY_COMMAND_RATE_WINDOW = 60  # 60 seconds window

# Rate limit message tracking for security commands
security_rate_limit_messages = defaultdict(float)
SECURITY_RATE_LIMIT_MESSAGE_COOLDOWN = 30  # Show rate limit message once per 30 seconds

# Captcha verification settings
captcha_verify_role_id = None  # Role to grant upon successful captcha

# Customizable verification panel text per guild
captcha_panel_texts = {}  # guild_id -> {"title": str, "description": str, "image": str}

# Default panel text
DEFAULT_PANEL_TITLE = "Verification Panel"
DEFAULT_PANEL_DESCRIPTION = (
    "Server access requires verification.\n"
    "Click 'Verify' to receive a visual CAPTCHA challenge.\n"
    "Enter the displayed code using the 'Enter Code' button to complete verification."
)

# Rate limiting for captcha requests
captcha_rate_limits = defaultdict(list)  # user_id -> [timestamp, timestamp, ...]
CAPTCHA_RATE_LIMIT = 3  # Max 3 requests per minute
CAPTCHA_RATE_WINDOW = 60  # 60 seconds window

# Active captcha sessions to prevent spam
active_captcha_sessions = set()  # Set of user_ids currently processing captcha

# Verify button usage tracking (user_id -> interaction_count)
verify_button_usage = defaultdict(int)  # Tracks how many times each user clicked verify
VERIFY_MAX_ATTEMPTS = 10  # Maximum verify attempts per user

# Rate limit message tracking for CAPTCHA rate limits (user_id -> last_message_time)
captcha_rate_limit_messages = defaultdict(float)  # Tracks when captcha rate limit message was last sent
CAPTCHA_RATE_LIMIT_MESSAGE_COOLDOWN = 60  # Show captcha rate limit message once per minute

def is_security_authorized(ctx):
    if security_authorized_role_id in [role.id for role in ctx.author.roles]:
        return True
    if ctx.author.id in security_authorized_ids:
        return True
    for role in ctx.author.roles:
        if role.id in security_authorized_ids:
            return True
    return False

def _check_security_command_rate_limit(user_id: int) -> bool:
    """Check if user is within rate limit for security commands"""
    current_time = time.time()
    user_requests = command_rate_limits[user_id]
    
    # Remove old requests outside the window
    user_requests[:] = [req_time for req_time in user_requests if current_time - req_time < SECURITY_COMMAND_RATE_WINDOW]
    
    # Check if user has exceeded rate limit
    if len(user_requests) >= SECURITY_COMMAND_RATE_LIMIT:
        return False
    
    return True

def _add_security_command_rate_limit_request(user_id: int):
    """Add a request to the security command rate limit tracker"""
    current_time = time.time()
    command_rate_limits[user_id].append(current_time)

async def _handle_security_rate_limit(ctx, command_name: str) -> bool:
    """Handle rate limiting for security commands. Returns True if rate limited."""
    user_id = ctx.author.id
    
    if not _check_security_command_rate_limit(user_id):
        current_time = time.time()
        last_rate_limit_message = security_rate_limit_messages[user_id]
        
        # Show rate limit message only once per cooldown period
        if current_time - last_rate_limit_message >= SECURITY_RATE_LIMIT_MESSAGE_COOLDOWN:
            security_rate_limit_messages[user_id] = current_time
            await ctx.send(f"⏰ **Rate limit exceeded!** You can only use {SECURITY_COMMAND_RATE_LIMIT} security commands per minute. Please wait and try again.")
        
        # Delete the command message to reduce spam
        try:
            await ctx.message.delete()
        except discord.Forbidden:
            print(f"[SECURITY] Bot lacks permission to delete command message")
        except discord.NotFound:
            print(f"[SECURITY] Command message already deleted")
        except discord.HTTPException as e:
            print(f"[SECURITY] HTTP error deleting command message: {e}")
        except Exception as e:
            print(f"[SECURITY] Unexpected error deleting command message: {e}")
        
        return True  # Rate limited
    
    # Add to rate limit tracker
    _add_security_command_rate_limit_request(user_id)
    return False  # Not rate limited

# Global Security Filter Variables
no_avatar_filter_enabled = False
no_avatar_action = None
no_avatar_timeout_duration = None

account_age_filter_enabled = False
account_age_min_days = None
account_age_action = None
account_age_timeout_duration = None

# Regex moderation settings per guild
# Structure: { guild_id: { name: {"pattern": str, "compiled": Pattern, "channels": set[int], "exempt_users": set[int], "exempt_roles": set[int]} } }
regex_settings_by_guild = {}

# Security settings file path
SECURITY_SETTINGS_FILE = "security_settings.json"

# Security settings save/load functions
def save_security_settings():
    """Güvenlik ayarlarını JSON dosyasına kaydet"""
    try:
        # Regex ayarlarını kaydetmek için compiled pattern'ları çıkar
        regex_data = {}
        for guild_id, rules in regex_settings_by_guild.items():
            regex_data[str(guild_id)] = {}
            for rule_name, rule_data in rules.items():
                regex_data[str(guild_id)][rule_name] = {
                    "pattern": rule_data.get("pattern", ""),
                    "channels": list(rule_data.get("channels", set())),
                    "exempt_users": list(rule_data.get("exempt_users", set())),
                    "exempt_roles": list(rule_data.get("exempt_roles", set()))
                }
        
        # Captcha panel texts'i kaydet
        captcha_data = {}
        for guild_id, panel_data in captcha_panel_texts.items():
            captcha_data[str(guild_id)] = panel_data
        
        settings = {
            "security_authorized_ids": list(security_authorized_ids),
            "no_avatar_filter_enabled": no_avatar_filter_enabled,
            "no_avatar_action": no_avatar_action,
            "no_avatar_timeout_duration": no_avatar_timeout_duration,
            "account_age_filter_enabled": account_age_filter_enabled,
            "account_age_min_days": account_age_min_days,
            "account_age_action": account_age_action,
            "account_age_timeout_duration": account_age_timeout_duration,
            "captcha_verify_role_id": captcha_verify_role_id,
            "captcha_panel_texts": captcha_data,
            "regex_settings_by_guild": regex_data,
            "security_audit_log": security_audit_log[-50:] if security_audit_log else []  # Son 50 kayıt
        }
        
        with open(SECURITY_SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
        
        print(f"[SECURITY] Settings saved to {SECURITY_SETTINGS_FILE}")
        return True
    except Exception as e:
        print(f"[SECURITY] Error saving settings: {e}")
        return False

def load_security_settings():
    """Güvenlik ayarlarını JSON dosyasından yükle"""
    global security_authorized_ids, no_avatar_filter_enabled, no_avatar_action, no_avatar_timeout_duration
    global account_age_filter_enabled, account_age_min_days, account_age_action, account_age_timeout_duration
    global captcha_verify_role_id, captcha_panel_texts, regex_settings_by_guild, security_audit_log
    
    try:
        if not Path(SECURITY_SETTINGS_FILE).exists():
            print(f"[SECURITY] Settings file {SECURITY_SETTINGS_FILE} not found, using defaults")
            return False
        
        with open(SECURITY_SETTINGS_FILE, 'r', encoding='utf-8') as f:
            settings = json.load(f)
        
        # Güvenlik yetkili ID'leri yükle
        security_authorized_ids = set(settings.get("security_authorized_ids", []))
        
        # No-avatar filter ayarları
        no_avatar_filter_enabled = settings.get("no_avatar_filter_enabled", False)
        no_avatar_action = settings.get("no_avatar_action", None)
        no_avatar_timeout_duration = settings.get("no_avatar_timeout_duration", None)
        
        # Account age filter ayarları
        account_age_filter_enabled = settings.get("account_age_filter_enabled", False)
        account_age_min_days = settings.get("account_age_min_days", None)
        account_age_action = settings.get("account_age_action", None)
        account_age_timeout_duration = settings.get("account_age_timeout_duration", None)
        
        # Captcha ayarları
        captcha_verify_role_id = settings.get("captcha_verify_role_id", None)
        
        # Captcha panel texts yükle
        captcha_data = settings.get("captcha_panel_texts", {})
        captcha_panel_texts.clear()
        for guild_id_str, panel_data in captcha_data.items():
            captcha_panel_texts[int(guild_id_str)] = panel_data
        
        # Regex ayarları yükle
        regex_data = settings.get("regex_settings_by_guild", {})
        regex_settings_by_guild.clear()
        for guild_id_str, rules in regex_data.items():
            guild_id = int(guild_id_str)
            regex_settings_by_guild[guild_id] = {}
            for rule_name, rule_data in rules.items():
                pattern = rule_data.get("pattern", "")
                if pattern:
                    try:
                        # Pattern'ı yeniden compile et
                        pattern_text, flags_letters = _parse_pattern_and_flags(pattern)
                        compiled = _compile_with_flags(pattern_text, flags_letters)
                        
                        regex_settings_by_guild[guild_id][rule_name] = {
                            "pattern": pattern,
                            "compiled": compiled,
                            "channels": set(rule_data.get("channels", [])),
                            "exempt_users": set(rule_data.get("exempt_users", [])),
                            "exempt_roles": set(rule_data.get("exempt_roles", []))
                        }
                    except Exception as e:
                        print(f"[SECURITY] Error compiling regex pattern '{pattern}': {e}")
        
        # Audit log yükle
        security_audit_log.clear()
        security_audit_log.extend(settings.get("security_audit_log", []))
        
        print(f"[SECURITY] Settings loaded from {SECURITY_SETTINGS_FILE}")
        print(f"[SECURITY] Loaded: {len(security_authorized_ids)} authorized IDs, {len(regex_settings_by_guild)} guild regex settings")
        return True
    except Exception as e:
        print(f"[SECURITY] Error loading settings: {e}")
        return False

def auto_save_security_settings():
    """Güvenlik ayarlarını otomatik kaydet (değişiklik sonrası çağrılır)"""
    try:
        save_security_settings()
    except Exception as e:
        print(f"[SECURITY] Auto-save failed: {e}")


# ---------------- Bot Detection (Integrated from lastguard.py) ----------------
# Rule storage per guild
bot_detection_rules = {}

# Tracking data per user for behavior analysis
bot_detection_data = defaultdict(lambda: {
    "messages": [],  # [(timestamp, content, channel_id, message_id, is_reply), ...]
    "last_activity": 0
})


# Data persistence settings (same as lastguard)
DATA_FILE_PATH = "lastguard_data.json"

def _save_bot_data():
    """Save bot detection data to JSON file"""
    try:
        # Convert defaultdict to regular dict and sets to lists for JSON serialization
        data_to_save = {
            "bot_detection_rules": {},
            "bot_detection_data": {},
            "verify_button_usage": dict(verify_button_usage),
            "captcha_panel_texts": captcha_panel_texts,
            "regex_settings_by_guild": {}
        }
        
        # Convert bot detection rules
        for guild_id, rules in bot_detection_rules.items():
            data_to_save["bot_detection_rules"][str(guild_id)] = {}
            for rule_name, settings in rules.items():
                rule_data = settings.copy()
                # Convert sets to lists
                rule_data["channels"] = list(rule_data.get("channels", set()))
                rule_data["exempt_users"] = list(rule_data.get("exempt_users", set()))
                rule_data["exempt_roles"] = list(rule_data.get("exempt_roles", set()))
                data_to_save["bot_detection_rules"][str(guild_id)][rule_name] = rule_data
        
        # Convert bot detection tracking data
        for user_id, user_data in bot_detection_data.items():
            data_to_save["bot_detection_data"][str(user_id)] = dict(user_data)
        
        # Convert regex settings
        for guild_id, rules in regex_settings_by_guild.items():
            data_to_save["regex_settings_by_guild"][str(guild_id)] = {}
            for rule_name, settings in rules.items():
                rule_data = settings.copy()
                # Remove compiled regex (will be recompiled on load)
                if "compiled" in rule_data:
                    del rule_data["compiled"]
                # Convert sets to lists
                rule_data["channels"] = list(rule_data.get("channels", set()))
                rule_data["exempt_users"] = list(rule_data.get("exempt_users", set()))
                rule_data["exempt_roles"] = list(rule_data.get("exempt_roles", set()))
                data_to_save["regex_settings_by_guild"][str(guild_id)][rule_name] = rule_data
        
        with open(DATA_FILE_PATH, 'w', encoding='utf-8') as f:
            json.dump(data_to_save, f, indent=2, ensure_ascii=False)
        
        print(f"[persistence] Data saved to {DATA_FILE_PATH}")
        return True
    except Exception as e:
        print(f"[persistence] Error saving data: {e}")
        return False

def _load_bot_data():
    """Load bot detection data from JSON file"""
    global bot_detection_rules, bot_detection_data, verify_button_usage, captcha_panel_texts, regex_settings_by_guild
    
    try:
        if not os.path.exists(DATA_FILE_PATH):
            print(f"[persistence] No data file found at {DATA_FILE_PATH}, starting fresh")
            return
        
        with open(DATA_FILE_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Load bot detection rules
        if "bot_detection_rules" in data:
            bot_detection_rules.clear()
            for guild_id_str, rules in data["bot_detection_rules"].items():
                guild_id = int(guild_id_str)
                bot_detection_rules[guild_id] = {}
                for rule_name, settings in rules.items():
                    rule_data = settings.copy()
                    # Convert lists back to sets
                    rule_data["channels"] = set(rule_data.get("channels", []))
                    rule_data["exempt_users"] = set(rule_data.get("exempt_users", []))
                    rule_data["exempt_roles"] = set(rule_data.get("exempt_roles", []))
                    bot_detection_rules[guild_id][rule_name] = rule_data
        
        # Load bot detection tracking data
        if "bot_detection_data" in data:
            bot_detection_data.clear()
            for user_id_str, user_data in data["bot_detection_data"].items():
                user_id = int(user_id_str)
                bot_detection_data[user_id] = user_data
        
        # Load verify button usage
        if "verify_button_usage" in data:
            verify_button_usage.clear()
            for user_id_str, count in data["verify_button_usage"].items():
                verify_button_usage[int(user_id_str)] = count
        
        # Load captcha panel texts
        if "captcha_panel_texts" in data:
            captcha_panel_texts.clear()
            captcha_panel_texts.update(data["captcha_panel_texts"])
        
        # Load regex settings
        if "regex_settings_by_guild" in data:
            regex_settings_by_guild.clear()
            for guild_id_str, rules in data["regex_settings_by_guild"].items():
                guild_id = int(guild_id_str)
                regex_settings_by_guild[guild_id] = {}
                for rule_name, settings in rules.items():
                    rule_data = settings.copy()
                    # Convert lists back to sets
                    rule_data["channels"] = set(rule_data.get("channels", []))
                    rule_data["exempt_users"] = set(rule_data.get("exempt_users", []))
                    rule_data["exempt_roles"] = set(rule_data.get("exempt_roles", []))
                    # Recompile regex pattern
                    if "pattern" in rule_data:
                        try:
                            pattern_text, flags_letters = _parse_pattern_and_flags(rule_data["pattern"])
                            rule_data["compiled"] = _compile_with_flags(pattern_text, flags_letters)
                        except Exception as e:
                            print(f"[persistence] Error recompiling regex for {rule_name}: {e}")
                            continue
                    regex_settings_by_guild[guild_id][rule_name] = rule_data
        
        print(f"[persistence] Data loaded from {DATA_FILE_PATH}")
        print(f"[persistence] Loaded {len(bot_detection_rules)} guilds with bot detection rules")
        print(f"[persistence] Loaded {len(bot_detection_data)} users with tracking data")
        
    except Exception as e:
        print(f"[persistence] Error loading data: {e}")


def _check_bot_behavior(
    user_id: int,
    guild_id: int,
    message_content: str,
    channel_id: int,
    message_id: int,
    member: discord.Member = None,
    message_obj: discord.Message = None,
) -> tuple[bool, str, str]:
    """
    Kullanıcının mesaj ve hesap özelliklerine göre bot benzeri davranış sergileyip sergilemediğini kontrol eder.
    Dönüş: (tespit_edildi_mi, kural_adı, neden)
    """
    if guild_id not in bot_detection_rules:
        return False, "", ""

    guild_rules = bot_detection_rules[guild_id]
    current_time = time.time()
    user_data = bot_detection_data[user_id]

    for rule_name, settings in guild_rules.items():
        if not settings.get("enabled", False):
            continue

        monitored_channels = settings.get("channels", set())
        if monitored_channels and channel_id not in monitored_channels:
            continue

        logic_operator = settings.get("logic_operator", "or").lower()

        detection_results = {
            "repeated_messages": False,
            "total_same_messages": False,
            "consecutive_messages": False,
            "total_consecutive_messages": False,
            "account_age": False,
            "no_avatar": False,
        }

        detected_reasons: list[str] = []

        # Account age check
        if settings.get("check_account_age", False) and member:
            max_age_days = settings.get("max_account_age_days", 7)
            account_age_days = (discord.utils.utcnow() - member.created_at).days
            if account_age_days <= max_age_days:
                detection_results["account_age"] = True
                detected_reasons.append(f"account {account_age_days} days old (limit: {max_age_days} days)")

        # Avatar check
        if settings.get("check_no_avatar", False) and member:
            if member.avatar is None:
                detection_results["no_avatar"] = True
                detected_reasons.append("no profile picture")

        # Clean old messages outside the window
        time_window = settings.get("time_window", 300)
        user_data["messages"] = [
            msg for msg in user_data["messages"] if current_time - msg[0] <= time_window
        ]

        # Append current message (once) with reply info
        is_reply_message = False
        if message_obj and message_obj.reference:
            is_reply_message = True
        if not user_data["messages"] or user_data["messages"][-1][3] != message_id:
            user_data["messages"].append((current_time, message_content, channel_id, message_id, is_reply_message))
            user_data["last_activity"] = current_time

        # Repeated consecutive same messages
        repeated_threshold = settings.get("repeated_message_count", 0)
        if repeated_threshold > 0:
            relevant_messages = [
                msg for msg in user_data["messages"] if not monitored_channels or msg[2] in monitored_channels
            ]
            if len(relevant_messages) >= repeated_threshold:
                last_message_content = (relevant_messages[-1][1] or "").lower().strip()
                consecutive_same_count = 0
                for i in range(len(relevant_messages) - 1, -1, -1):
                    if (relevant_messages[i][1] or "").lower().strip() == last_message_content:
                        consecutive_same_count += 1
                    else:
                        break
                if consecutive_same_count >= repeated_threshold:
                    detection_results["repeated_messages"] = True
                    detected_reasons.append(
                        f"repeated '{last_message_content}' message {consecutive_same_count} times consecutively"
                    )

        # Total same messages in window
        total_same_threshold = settings.get("total_same_message_count", 0)
        if total_same_threshold > 0:
            relevant_messages = [
                msg for msg in user_data["messages"] if not monitored_channels or msg[2] in monitored_channels
            ]
            if len(relevant_messages) >= total_same_threshold:
                message_counts: dict[str, int] = {}
                for msg_data in relevant_messages:
                    content_key = (msg_data[1] or "").lower().strip()
                    if content_key:
                        message_counts[content_key] = message_counts.get(content_key, 0) + 1
                for content_key, count in message_counts.items():
                    if count >= total_same_threshold:
                        detection_results["total_same_messages"] = True
                        detected_reasons.append(f"sent '{content_key}' message {count} times in total")
                        break

        # Consecutive messages without replies
        consecutive_threshold = settings.get("consecutive_message_count", 0)
        if consecutive_threshold > 0:
            relevant_messages = [
                msg for msg in user_data["messages"] if not monitored_channels or msg[2] in monitored_channels
            ]
            recent_messages = relevant_messages[-consecutive_threshold:]
            if len(recent_messages) >= consecutive_threshold:
                consecutive_count = 0
                for msg_data in recent_messages:
                    if len(msg_data) >= 5:
                        _, content, ch_id, _, is_discord_reply = msg_data
                    else:
                        _, content, ch_id, _ = msg_data
                        is_discord_reply = False
                    content_lower = (content or "").lower().strip()
                    has_user_mention = (
                        "@" in content_lower
                        and (
                            re.search(r"<@!?\d+>", content_lower)
                            or re.search(r"<@&\d+>", content_lower)
                            or "@everyone" in content_lower
                            or "@here" in content_lower
                        )
                    )
                    is_reply = is_discord_reply or has_user_mention
                    if not is_reply:
                        consecutive_count += 1
                    else:
                        consecutive_count = 0
                if consecutive_count >= consecutive_threshold:
                    detection_results["consecutive_messages"] = True
                    detected_reasons.append(f"{consecutive_count} consecutive messages without replies")

        # Total no-reply messages in window
        total_consecutive_threshold = settings.get("total_consecutive_message_count", 0)
        if total_consecutive_threshold > 0:
            relevant_messages = [
                msg for msg in user_data["messages"] if not monitored_channels or msg[2] in monitored_channels
            ]
            if len(relevant_messages) >= total_consecutive_threshold:
                total_non_reply_count = 0
                for msg_data in relevant_messages:
                    if len(msg_data) >= 5:
                        _, content, ch_id, _, is_discord_reply = msg_data
                    else:
                        _, content, ch_id, _ = msg_data
                        is_discord_reply = False
                    content_lower = (content or "").lower().strip()
                    has_user_mention = (
                        "@" in content_lower
                        and (
                            re.search(r"<@!?\d+>", content_lower)
                            or re.search(r"<@&\d+>", content_lower)
                            or "@everyone" in content_lower
                            or "@here" in content_lower
                        )
                    )
                    is_reply = is_discord_reply or has_user_mention
                    if not is_reply:
                        total_non_reply_count += 1
                if total_non_reply_count >= total_consecutive_threshold:
                    detection_results["total_consecutive_messages"] = True
                    detected_reasons.append(f"{total_non_reply_count} messages without replies in total")

        # Combine message criteria
        message_logic_operator = settings.get("message_logic_operator", "or").lower()
        message_criteria = [
            detection_results["repeated_messages"] and settings.get("repeated_message_count", 0) > 0,
            detection_results["total_same_messages"] and settings.get("total_same_message_count", 0) > 0,
            detection_results["consecutive_messages"] and settings.get("consecutive_message_count", 0) > 0,
            detection_results["total_consecutive_messages"] and settings.get("total_consecutive_message_count", 0) > 0,
        ]
        enabled_message_criteria = [result for result in message_criteria if result is not False]
        triggered_message_criteria = [result for result in message_criteria if result is True]

        message_criteria_satisfied = False
        if enabled_message_criteria:
            if message_logic_operator == "and":
                message_criteria_satisfied = (
                    len(triggered_message_criteria) == len(enabled_message_criteria)
                    and len(triggered_message_criteria) > 0
                )
            else:
                message_criteria_satisfied = len(triggered_message_criteria) > 0

        # Account/avatar criteria (OR)
        account_criteria = [
            detection_results["account_age"] and settings.get("check_account_age", False),
            detection_results["no_avatar"] and settings.get("check_no_avatar", False),
        ]
        enabled_account_criteria = [result for result in account_criteria if result is not False]
        triggered_account_criteria = [result for result in account_criteria if result is True]
        account_criteria_satisfied = False
        if enabled_account_criteria:
            account_criteria_satisfied = len(triggered_account_criteria) > 0

        overall_criteria = []
        if enabled_message_criteria:
            overall_criteria.append(message_criteria_satisfied)
        if enabled_account_criteria:
            overall_criteria.append(account_criteria_satisfied)
        if not overall_criteria:
            continue

        rule_triggered = False
        if logic_operator == "and":
            rule_triggered = all(overall_criteria)
        else:
            rule_triggered = any(overall_criteria)

        if rule_triggered and detected_reasons:
            operator_text = " AND " if logic_operator == "and" else " OR "
            reason_text = operator_text.join(detected_reasons)
            return True, rule_name, reason_text

    return False, "", ""


async def _handle_bot_detection(member: discord.Member, guild_id: int, rule_name: str, detected_reason: str):
    """Tespit edilen bot davranışı için gerekli işlemleri uygular."""
    if guild_id not in bot_detection_rules or rule_name not in bot_detection_rules[guild_id]:
        return

    settings = bot_detection_rules[guild_id][rule_name]
    action = settings.get("action", "notify")

    exempt_users = settings.get("exempt_users", set())
    exempt_roles = settings.get("exempt_roles", set())

    if member.id in exempt_users:
        return
    if any(role.id in exempt_roles for role in getattr(member, "roles", [])):
        return

    # Bildirim gönder
    notification_channel_id = settings.get("notification_channel")
    if notification_channel_id:
        notification_channel = member.guild.get_channel(notification_channel_id)
        if notification_channel:
            embed = discord.Embed(
                title="🤖 Bot Behavior Detected",
                description=(
                    f"**User:** {member.mention} ({member.id})\n"
                    f"**Rule:** {rule_name}\n"
                    f"**Reason:** {detected_reason}"
                ),
                color=discord.Color.orange(),
            )
            embed.add_field(
                name="Account Created",
                value=member.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                inline=True,
            )
            embed.add_field(
                name="Joined Server",
                value=member.joined_at.strftime("%Y-%m-%d %H:%M:%S UTC") if member.joined_at else "Unknown",
                inline=True,
            )
            embed.add_field(name="Action Taken", value=action.title(), inline=True)
            try:
                await notification_channel.send(embed=embed)
            except Exception as e:
                print(f"[bot_detection] Notification send error: {e}")

    # İşlem uygula
    try:
        if action == "timeout":
            timeout_duration = settings.get("timeout_duration", 60)
            until = discord.utils.utcnow() + timedelta(minutes=timeout_duration)
            await member.edit(
                timeout=until,
                reason=f"Bot behavior detected ({rule_name}): {detected_reason}",
            )
        elif action == "kick":
            await member.kick(reason=f"Bot behavior detected ({rule_name}): {detected_reason}")
        elif action == "ban":
            await member.ban(reason=f"Bot behavior detected ({rule_name}): {detected_reason}")
        # notify: only notification
    except Exception as e:
        print(f"[bot_detection] Action error: {e}")


def _parse_pattern_and_flags(raw_text):
    text = (raw_text or "").strip()
    flags_letters_parts = []

    # Support trailing --flags imsx style
    m = re.search(r"\s--flags\s+([A-Za-z]+)\s*$", text)
    if m:
        flags_letters_parts.append(m.group(1))
        text = text[: m.start()].strip()

    # Support /pattern/flags style
    if len(text) >= 2 and text[0] == "/" and "/" in text[1:]:
        last_slash = text.rfind("/")
        body = text[1:last_slash]
        trailing = text[last_slash + 1 :].strip()
        if trailing and re.fullmatch(r"[A-Za-z]+", trailing):
            flags_letters_parts.append(trailing)
            # Unescape \/ to /
            body = body.replace("\\/", "/")
            text = body

    # Merge letters while preserving order and uniqueness
    seen = set()
    letters = ""
    for part in flags_letters_parts:
        for ch in part:
            cl = ch.lower()
            if cl not in seen:
                seen.add(cl)
                letters += cl

    return text, letters


def _compile_with_flags(pattern_text, flags_letters):
    flag_map = {
        "i": re.IGNORECASE,
        "m": re.MULTILINE,
        "s": re.DOTALL,
        "x": re.VERBOSE,
        "a": re.ASCII,
        "u": re.UNICODE,
        "l": re.LOCALE,
    }
    flags_value = 0
    for ch in flags_letters or "":
        flags_value |= flag_map.get(ch.lower(), 0)
    return _REGEX_ENGINE.compile(pattern_text, flags_value)

# Security: Safe regex search with timeout to prevent ReDoS attacks
def _safe_regex_search(compiled_pattern, text, timeout_seconds=1):
    """
    Safely search regex with timeout to prevent ReDoS (Regular Expression Denial of Service) attacks
    """
    if not text:
        return None
    
    # Limit text length to prevent memory issues
    MAX_TEXT_LENGTH = 10000
    if len(text) > MAX_TEXT_LENGTH:
        text = text[:MAX_TEXT_LENGTH]
    
    result = [None]
    exception = [None]
    
    def search_worker():
        try:
            result[0] = compiled_pattern.search(text)
        except Exception as e:
            exception[0] = e
    
    # Use threading for timeout (signal doesn't work well with Discord.py)
    thread = threading.Thread(target=search_worker, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)
    
    if thread.is_alive():
        # Timeout occurred - potential ReDoS attack
        print(f"[SECURITY] Regex timeout detected - potential ReDoS attack blocked")
        return None
    
    if exception[0]:
        print(f"[SECURITY] Regex error: {exception[0]}")
        return None
        
    return result[0]

# Message moderation via regex
@bot.event
async def on_message(message: discord.Message):
    # Ignore bot messages
    if message.author.bot:
        return
    # If DM, do not process commands or moderation
    if message.guild is None:
        return
    # Let command processor run only in guilds
    if isinstance(bot.command_prefix, str) and message.content.startswith(bot.command_prefix):
        await bot.process_commands(message)
        return

    # ---------------- Bot detection check ----------------
    try:
        member_obj = message.author if isinstance(message.author, discord.Member) else None
        is_detected, triggered_rule, detected_reason = _check_bot_behavior(
            message.author.id,
            message.guild.id,
            message.content or "",
            message.channel.id,
            message.id,
            member_obj,
            message,
        )
        if is_detected and triggered_rule and member_obj:
            await _handle_bot_detection(member_obj, message.guild.id, triggered_rule, detected_reason)
    except Exception as e:
        print(f"[bot_detection] Error in bot detection: {e}")
    guild_rules = regex_settings_by_guild.get(message.guild.id)
    if not guild_rules:
        return
    channel_id = message.channel.id
    for rule in guild_rules.values():
        channels = rule.get("channels", set())
        compiled = rule.get("compiled")
        if not compiled or not channels:
            continue
        # Security: Use safe regex search to prevent ReDoS attacks
        if channel_id in channels and _safe_regex_search(compiled, message.content or ""):
            # Exemptions: users or roles
            exempt_users = rule.get("exempt_users", set())
            exempt_roles = rule.get("exempt_roles", set())
            if message.author.id in exempt_users:
                continue
            author_roles = getattr(message.author, "roles", [])
            if any(r.id in exempt_roles for r in author_roles):
                continue
            try:
                await message.delete()
            except discord.Forbidden:
                print(f"[SECURITY] Bot lacks permission to delete message in {message.channel}")
            except discord.NotFound:
                print(f"[SECURITY] Message already deleted in {message.channel}")
            except discord.HTTPException as e:
                print(f"[SECURITY] HTTP error deleting message: {e}")
            except Exception as e:
                print(f"[SECURITY] Unexpected error deleting message: {e}")
            break

# Button interaction handler - Add this to fix the interaction failed issue
@bot.event
async def on_interaction(interaction):
    if interaction.type == discord.InteractionType.component:
        custom_id = interaction.data.get("custom_id", "")
        
        # Handle CAPTCHA verification button
        if custom_id == "captcha_verify_button":
            user_id = interaction.user.id
            
            # Check if user has exceeded verify attempts - COMPLETELY SILENT
            if verify_button_usage[user_id] >= VERIFY_MAX_ATTEMPTS:
                # Silently ignore - no response at all
                return
            
            # Check if verification role is set
            if captcha_verify_role_id is None:
                await interaction.response.send_message(
                    "Verification role is not set. Please contact an administrator.",
                    ephemeral=True,
                )
                return

            # Check rate limiting BEFORE incrementing usage count
            if not _check_captcha_rate_limit(user_id):
                current_time = time.time()
                last_rate_limit_message = captcha_rate_limit_messages[user_id]
                
                # Show rate limit message only once per minute
                if current_time - last_rate_limit_message >= CAPTCHA_RATE_LIMIT_MESSAGE_COOLDOWN:
                    captcha_rate_limit_messages[user_id] = current_time
                    await interaction.response.send_message(
                        f"⏰ Rate limit exceeded. You can only request {CAPTCHA_RATE_LIMIT} captchas per minute. Please wait and try again.",
                        ephemeral=True,
                    )
                # If rate limit message was sent recently, silently ignore
                # IMPORTANT: Don't increment usage count when rate limited
                return
            
            # Only increment usage count AFTER passing rate limit check
            verify_button_usage[user_id] += 1

            # Remove any existing active session to allow fresh captcha
            if user_id in active_captcha_sessions:
                active_captcha_sessions.discard(user_id)
                print(f"[captcha] Removed existing session for user {user_id} to generate fresh captcha")

            # Already has role?
            member = interaction.user
            if isinstance(member, discord.Member):
                if any(r.id == captcha_verify_role_id for r in getattr(member, "roles", [])):
                    await interaction.response.send_message(
                        "You are already verified.", ephemeral=True
                    )
                    return

            # Add to active sessions
            active_captcha_sessions.add(user_id)

            try:
                # Generate fresh captcha code each time
                code = _generate_captcha_code()
                # Security: Log hash instead of actual code to prevent bypass
                import hashlib
                code_hash = hashlib.sha256(code.encode()).hexdigest()[:8]
                print(f"[captcha] Generated captcha (hash: {code_hash}) for user {user_id} (attempt #{verify_button_usage[user_id]}), PIL available: {_PIL_AVAILABLE}")

                # Add to rate limit tracker only when captcha is successfully generated
                _add_captcha_rate_limit_request(user_id)

                # Defer first, then send image
                await interaction.response.defer(ephemeral=True)
                
                # Text image CAPTCHA
                if _PIL_AVAILABLE:
                    try:
                        img_bytes = _create_text_image(code)
                        file = discord.File(io.BytesIO(img_bytes), filename="captcha.png")
                        embed = discord.Embed(
                            title="🔐 Security Verification",
                            description=f"Please read the code from the image below and click 'Enter Code' to input it.\n\n**Attempt: {verify_button_usage[user_id]}/{VERIFY_MAX_ATTEMPTS}**",
                            color=discord.Color.blue()
                        )
                        embed.set_image(url="attachment://captcha.png")
                        view = CaptchaCodeEntryView(expected_code=code, verify_role_id=captcha_verify_role_id, user_id=user_id)
                        await interaction.followup.send(embed=embed, file=file, view=view, ephemeral=True)
                        return
                    except Exception as e:
                        print(f"[captcha] Text image creation failed: {e}")

                # Fallback: Simple text
                embed = discord.Embed(
                    title="🔐 Security Verification",
                    description=f"**Code: `{code}`**\n\nPlease enter the code above by clicking 'Enter Code'.\n\n**Attempt: {verify_button_usage[user_id]}/{VERIFY_MAX_ATTEMPTS}**",
                    color=discord.Color.green()
                )
                view = CaptchaCodeEntryView(expected_code=code, verify_role_id=captcha_verify_role_id, user_id=user_id)
                await interaction.followup.send(embed=embed, view=view, ephemeral=True)

            except Exception as e:
                print(f"[captcha] Error in verify_button: {e}")
                # Remove from active sessions on error
                active_captcha_sessions.discard(user_id)
                try:
                    await interaction.followup.send("An error occurred while generating captcha. Please try again.", ephemeral=True)
                except discord.Forbidden:
                    print(f"[SECURITY] Bot lacks permission to send followup message")
                except discord.HTTPException as e:
                    print(f"[SECURITY] HTTP error sending followup message: {e}")
                except Exception as e:
                    print(f"[SECURITY] Unexpected error sending followup message: {e}")
            return
            
        # Handle CAPTCHA code entry button  
        if custom_id == "captcha_enter_code":
            # This should be handled by the CaptchaCodeEntryView
            return

# Define or update a regex rule
@bot.command(name="regex")
async def define_regex(ctx, regexsettingsname: str, *, regexcommand: str):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    # Security: Rate limiting
    if await _handle_security_rate_limit(ctx, "regex"):
        return
    name_key = regexsettingsname.strip().lower()
    # Accept extended syntaxes: /pattern/flags or plain pattern with optional --flags i m s x ...
    pattern_text, flags_letters = _parse_pattern_and_flags(regexcommand)
    try:
        compiled = _compile_with_flags(pattern_text, flags_letters)
    except re.error as e:
        await ctx.send(f"Invalid regex: {e}")
        return
    guild_id = ctx.guild.id
    if guild_id not in regex_settings_by_guild:
        regex_settings_by_guild[guild_id] = {}
    settings = regex_settings_by_guild[guild_id].get(name_key, {"channels": set(), "exempt_users": set(), "exempt_roles": set()})
    settings["pattern"] = regexcommand
    settings["compiled"] = compiled
    regex_settings_by_guild[guild_id][name_key] = settings
    # Auto-save settings
    auto_save_security_settings()
    if settings["channels"]:
        ch_mentions = ", ".join(f"<#{cid}>" for cid in settings["channels"])
        await ctx.send(
            f"Regex setting updated: `{regexsettingsname}`\n"
            f"Pattern: `{regexcommand}`\n"
            f"Engine: `{_REGEX_ENGINE_NAME}`  Flags: `{flags_letters or '-'}`\n"
            f"Applied channels: {ch_mentions}"
        )
    else:
        await ctx.send(
            f"Regex setting saved: `{regexsettingsname}`\n"
            f"Pattern: `{regexcommand}`\n"
            f"Engine: `{_REGEX_ENGINE_NAME}`  Flags: `{flags_letters or '-'}`\n"
            f"No channels assigned yet. Use `!setregexsettings {regexsettingsname} <channels>` to assign."
        )

# Assign channels to a regex rule
@bot.command(name="setregexsettings")
async def set_regex_settings(ctx, regexsettingsname: str, *, channels: str):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    guild_id = ctx.guild.id
    name_key = regexsettingsname.strip().lower()
    guild_rules = regex_settings_by_guild.get(guild_id)
    if not guild_rules or name_key not in guild_rules:
        await ctx.send("Please create the regex rule first: `!regex <regexsettingsname> <regex>`")
        return
    tokens = channels.replace(",", " ").split()
    lower_tokens = [t.lower() for t in tokens]
    selected: set[int] = set()
    invalid: list[str] = []

    # Helper: parse channel-like token into channel id (if valid)
    def _parse_channel_token(token: str):
        raw = token.strip()
        if raw.startswith("<#") and raw.endswith(">"):
            raw = raw[2:-1]
        try:
            cid_local = int(raw)
        except ValueError:
            return None
        channel_local = ctx.guild.get_channel(cid_local)
        if channel_local is None:
            return None
        return cid_local

    if "allchannel" in lower_tokens:
        # Start with all text channels
        for ch in ctx.guild.text_channels:
            selected.add(ch.id)

        if "notchannel" in lower_tokens:
            idx = lower_tokens.index("notchannel")
            exclude_tokens = tokens[idx + 1 :]
            if not exclude_tokens:
                # No exclusions provided; proceed with all text channels
                pass
            else:
                exclude_ids: set[int] = set()
                for tok in exclude_tokens:
                    cid = _parse_channel_token(tok)
                    if cid is None:
                        invalid.append(tok)
                    else:
                        exclude_ids.add(cid)
                selected -= exclude_ids
    else:
        if "notchannel" in lower_tokens:
            await ctx.send("Use `notchannel` only together with `allchannel`. Example: `!setregexsettings spamRule allchannel notchannel #channel1 #channel2`")
            return
        for tok in tokens:
            cid = _parse_channel_token(tok)
            if cid is None:
                invalid.append(tok)
                continue
            selected.add(cid)

    if not selected:
        await ctx.send("Please specify valid channels. Examples: `!setregexsettings spamRule #general #chat` or `!setregexsettings spamRule allchannel notchannel #log #mod`")
        return

    guild_rules[name_key]["channels"] = selected
    # Auto-save settings
    auto_save_security_settings()
    ch_mentions = ", ".join(f"<#{cid}>" for cid in selected)
    msg = f"Applied channels updated for `{regexsettingsname}`: {ch_mentions}"
    if invalid:
        msg += f"\nIgnored/Invalid: {' '.join(invalid)}"
    await ctx.send(msg)

# Set exemptions (users or roles) for a regex rule
@bot.command(name="setregexexempt")
async def set_regex_exempt(ctx, regexsettingsname: str, kind: str, *, targets: str):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    guild_id = ctx.guild.id
    name_key = regexsettingsname.strip().lower()
    guild_rules = regex_settings_by_guild.get(guild_id)
    if not guild_rules or name_key not in guild_rules:
        await ctx.send("Please create the regex rule first: `!regex <regexsettingsname> <regex>`")
        return
    kind_l = kind.strip().lower()
    if kind_l not in ("users", "roles"):
        await ctx.send("Please specify a type: `users` or `roles`. Example: `!setregexexempt spam users @u1 @u2` or `!setregexexempt spam roles @role1 @role2`")
        return
    tokens = targets.replace(",", " ").split()
    selected: set[int] = set()
    invalid = []
    for tok in tokens:
        raw = tok.strip()
        # Normalize mentions
        if kind_l == "roles":
            if raw.startswith("<@&") and raw.endswith(">"):
                raw = raw[3:-1]
        else:  # users
            if raw.startswith("<@!") and raw.endswith(">"):
                raw = raw[3:-1]
            elif raw.startswith("<@") and raw.endswith(">"):
                raw = raw[2:-1]
        try:
            _id = int(raw)
        except ValueError:
            invalid.append(tok)
            continue
        if kind_l == "roles":
            role = ctx.guild.get_role(_id)
            if role is None:
                invalid.append(tok)
                continue
        else:
            member = ctx.guild.get_member(_id)
            if member is None:
                invalid.append(tok)
                continue
        selected.add(_id)
    if not selected:
        await ctx.send("Please specify valid targets. Examples:\n- `!setregexexempt spam users @alice @bob`\n- `!setregexexempt spam roles @Admin 123456789012345678`")
        return
    if kind_l == "roles":
        guild_rules[name_key]["exempt_roles"] = selected
        mentions = ", ".join(f"<@&{i}>" for i in selected)
        msg = f"Exempt roles updated for `{regexsettingsname}`: {mentions}"
    else:
        guild_rules[name_key]["exempt_users"] = selected
        mentions = ", ".join(f"<@{i}>" for i in selected)
        msg = f"Exempt users updated for `{regexsettingsname}`: {mentions}"
    
    # Auto-save settings
    auto_save_security_settings()
    if invalid:
        msg += f"\nIgnored/Invalid: {' '.join(invalid)}"
    await ctx.send(msg)

# Show regex settings (all or specific)
@bot.command(name="regexsettings")
async def regexsettings(ctx, regexsettingsname: str = None):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    guild_id = ctx.guild.id
    guild_rules = regex_settings_by_guild.get(guild_id)
    if not guild_rules:
        await ctx.send("There are no regex settings defined in this server.")
        return

    def _mentions_list(ids: set[int], kind: str) -> str:
        if not ids:
            return "None"
        if kind == "channel":
            return ", ".join(f"<#{i}>" for i in ids)
        if kind == "user":
            return ", ".join(f"<@{i}>" for i in ids)
        if kind == "role":
            return ", ".join(f"<@&{i}>" for i in ids)
        return "None"

    if regexsettingsname:
        name_key = regexsettingsname.strip().lower()
        rule = guild_rules.get(name_key)
        if not rule:
            await ctx.send("No regex setting found with the specified name.")
            return
        pattern_text = rule.get("pattern", "-")
        channels = rule.get("channels", set())
        exempt_users = rule.get("exempt_users", set())
        exempt_roles = rule.get("exempt_roles", set())
        status = "Active" if channels else "Inactive"

        embed = discord.Embed(title=f"Regex Settings - {regexsettingsname}", color=discord.Color.blue())
        embed.add_field(name="Status", value=status, inline=False)
        embed.add_field(name="Pattern", value=f"`{pattern_text}`", inline=False)
        embed.add_field(name="Applied Channels", value=_mentions_list(channels, "channel"), inline=False)
        embed.add_field(name="Exempt Users", value=_mentions_list(exempt_users, "user"), inline=False)
        embed.add_field(name="Exempt Roles", value=_mentions_list(exempt_roles, "role"), inline=False)
        await ctx.send(embed=embed)
        return

    # List all rules
    embed = discord.Embed(title="Regex Settings", color=discord.Color.blue())
    for name_key, rule in guild_rules.items():
        pattern_text = rule.get("pattern", "-")
        channels = rule.get("channels", set())
        exempt_users = rule.get("exempt_users", set())
        exempt_roles = rule.get("exempt_roles", set())
        status = "Active" if channels else "Inactive"
        value = (
            f"Status: {status}\n"
            f"Pattern: `{pattern_text}`\n"
            f"Channels: {_mentions_list(channels, 'channel')}\n"
            f"Exempt Users: {_mentions_list(exempt_users, 'user')}\n"
            f"Exempt Roles: {_mentions_list(exempt_roles, 'role')}"
        )
        embed.add_field(name=name_key, value=value, inline=False)

    await ctx.send(embed=embed)

# Delete a regex setting by name
@bot.command(name="delregexsettings")
async def delregexsettings(ctx, regexsettingsname: str):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    guild_id = ctx.guild.id
    guild_rules = regex_settings_by_guild.get(guild_id)
    if not guild_rules:
        await ctx.send("There are no regex settings defined in this server.")
        return
    name_key = regexsettingsname.strip().lower()
    if name_key not in guild_rules:
        await ctx.send("No regex setting found with the specified name.")
        return
    del guild_rules[name_key]
    if not guild_rules:
        try:
            del regex_settings_by_guild[guild_id]
        except KeyError:
            pass
    # Auto-save settings
    auto_save_security_settings()
    await ctx.send(f"Regex setting deleted: `{regexsettingsname}`")

# on_member_join event (Security Filters)
@bot.event
async def on_member_join(member):
    if no_avatar_filter_enabled:
        if member.avatar is None:
            try:
                if no_avatar_action == "ban":
                    await member.ban(reason="No avatar provided")
                elif no_avatar_action == "kick":
                    await member.kick(reason="No avatar provided")
                elif no_avatar_action == "timeout":
                    timeout_duration = timedelta(minutes=no_avatar_timeout_duration)
                    until = discord.utils.utcnow() + timeout_duration
                    await member.edit(timeout=until, reason="No avatar provided")
            except Exception as e:
                print("No-avatar filter error:", e)
    if account_age_filter_enabled:
        account_age = (discord.utils.utcnow() - member.created_at).days
        if account_age < account_age_min_days:
            try:
                if account_age_action == "ban":
                    await member.ban(reason="Account age insufficient")
                elif account_age_action == "kick":
                    await member.kick(reason="Account age insufficient")
                elif account_age_action == "timeout":
                    timeout_duration = timedelta(minutes=account_age_timeout_duration)
                    until = discord.utils.utcnow() + timeout_duration
                    await member.edit(timeout=until, reason="Account age insufficient")
            except Exception as e:
                print("Account age filter error:", e)

# !noavatarfilter command
@bot.command(name="noavatarfilter")
async def noavatarfilter_command(ctx, state: str, mode: str = None, duration: int = None):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    # Security: Rate limiting
    if await _handle_security_rate_limit(ctx, "noavatarfilter"):
        return
    global no_avatar_filter_enabled, no_avatar_action, no_avatar_timeout_duration
    state = state.lower()
    if state == "on":
        no_avatar_filter_enabled = True
        # Auto-save settings
        auto_save_security_settings()
        if mode is not None:
            mode = mode.lower()
            if mode not in ["ban", "kick", "timeout"]:
                await ctx.send("Please enter a valid mode: ban, kick or timeout")
                return
            no_avatar_action = mode
            if mode == "timeout":
                if duration is None:
                    await ctx.send("In timeout mode, please specify a duration (in minutes).")
                    return
                no_avatar_timeout_duration = duration
        await ctx.send(f"No-avatar filter enabled. Mode: {no_avatar_action}" +
                       (f", Timeout: {no_avatar_timeout_duration} minutes" if no_avatar_action == "timeout" else ""))
    elif state == "off":
        no_avatar_filter_enabled = False
        # Auto-save settings
        auto_save_security_settings()
        await ctx.send("No-avatar filter disabled.")
    else:
        await ctx.send("Please type 'on' or 'off'.")

# !accountagefilter command
@bot.command(name="accountagefilter")
async def accountagefilter_command(ctx, state: str, min_age: int = None, mode: str = None, duration: int = None):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    # Security: Rate limiting
    if await _handle_security_rate_limit(ctx, "accountagefilter"):
        return
    global account_age_filter_enabled, account_age_min_days, account_age_action, account_age_timeout_duration
    state = state.lower()
    if state == "off":
        account_age_filter_enabled = False
        # Auto-save settings
        auto_save_security_settings()
        await ctx.send("Account age filter disabled.")
        return
    elif state == "on":
        if min_age is None or mode is None:
            await ctx.send("Please specify the minimum account age (in days) and a mode. Example: `!accountagefilter on 7 timeout 60`")
            return
        account_age_filter_enabled = True
        account_age_min_days = min_age
        # Auto-save settings
        auto_save_security_settings()
        mode = mode.lower()
        if mode not in ["ban", "kick", "timeout"]:
            await ctx.send("Please enter a valid mode: ban, kick or timeout")
            return
        account_age_action = mode
        if mode == "timeout":
            if duration is None:
                await ctx.send("In timeout mode, please specify a duration (in minutes).")
                return
            account_age_timeout_duration = duration
            await ctx.send(f"Account age filter enabled: Accounts younger than {min_age} days will be timed out for {duration} minutes.")
        else:
            await ctx.send(f"Account age filter enabled: Accounts younger than {min_age} days will be {mode}ned.")
    else:
        await ctx.send("Please type 'on' or 'off'.")

# ---------------- Security Commands ----------------
@bot.command(name="securityauthorizedadd")
async def securityauthorizedadd(ctx, identifier: str):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    # Security: Rate limiting
    if await _handle_security_rate_limit(ctx, "securityauthorizedadd"):
        return
    
    # Security: Check maximum limit
    if len(security_authorized_ids) >= MAX_SECURITY_AUTHORIZED_USERS:
        await ctx.send(f"⚠️ Maximum security authorization limit reached ({MAX_SECURITY_AUTHORIZED_USERS}). Remove an existing authorization first.")
        return
    
    try:
        id_val = int(identifier.strip("<@&>"))
    except ValueError:
        await ctx.send("Please provide a valid user or role ID.")
        return
    
    # Security: Check if ID already exists
    if id_val in security_authorized_ids:
        await ctx.send("This ID is already authorized for security commands.")
        return
    
    # Security: Validate that the ID exists in the guild
    is_valid = False
    target_type = "Unknown"
    target_name = "Unknown"
    
    # Check if it's a valid user
    member = ctx.guild.get_member(id_val)
    if member:
        is_valid = True
        target_type = "User"
        target_name = f"{member.display_name} ({member.name})"
    else:
        # Check if it's a valid role
        role = ctx.guild.get_role(id_val)
        if role:
            is_valid = True
            target_type = "Role"
            target_name = role.name
    
    if not is_valid:
        await ctx.send("⚠️ Invalid ID: No user or role found with this ID in the current guild.")
        return
    
    # Add to authorized list
    security_authorized_ids.add(id_val)
    
    # Auto-save settings
    auto_save_security_settings()
    
    # Security: Audit logging
    import datetime
    audit_entry = {
        "action": "SECURITY_AUTH_ADD",
        "executor": f"{ctx.author.name} ({ctx.author.id})",
        "target": f"{target_name} ({id_val})",
        "target_type": target_type,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "guild": f"{ctx.guild.name} ({ctx.guild.id})"
    }
    security_audit_log.append(audit_entry)
    
    # Keep only last 100 audit entries
    if len(security_audit_log) > 100:
        security_audit_log.pop(0)
    
    print(f"[SECURITY_AUDIT] {audit_entry['action']}: {audit_entry['executor']} authorized {audit_entry['target']}")
    
    await ctx.send(f"✅ {target_type} **{target_name}** is now authorized for security commands.\n📊 Total authorized: {len(security_authorized_ids)}/{MAX_SECURITY_AUTHORIZED_USERS}")

@bot.command(name="securityauthorizedremove")
async def securityauthorizedremove(ctx, identifier: str):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    # Security: Rate limiting
    if await _handle_security_rate_limit(ctx, "securityauthorizedremove"):
        return
    
    try:
        id_val = int(identifier.strip("<@&>"))
    except ValueError:
        await ctx.send("Please provide a valid user or role ID.")
        return
    
    if id_val not in security_authorized_ids:
        await ctx.send("⚠️ The specified ID was not found in the security authorized list.")
        return
    
    # Security: Get target info for audit
    target_type = "Unknown"
    target_name = "Unknown"
    
    # Check if it's a user
    member = ctx.guild.get_member(id_val)
    if member:
        target_type = "User"
        target_name = f"{member.display_name} ({member.name})"
    else:
        # Check if it's a role
        role = ctx.guild.get_role(id_val)
        if role:
            target_type = "Role"
            target_name = role.name
        else:
            # ID not found in guild but exists in authorized list (maybe left guild)
            target_name = f"ID: {id_val}"
    
    # Remove from authorized list
    security_authorized_ids.remove(id_val)
    
    # Auto-save settings
    auto_save_security_settings()
    
    # Security: Audit logging
    import datetime
    audit_entry = {
        "action": "SECURITY_AUTH_REMOVE",
        "executor": f"{ctx.author.name} ({ctx.author.id})",
        "target": f"{target_name} ({id_val})",
        "target_type": target_type,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "guild": f"{ctx.guild.name} ({ctx.guild.id})"
    }
    security_audit_log.append(audit_entry)
    
    # Keep only last 100 audit entries
    if len(security_audit_log) > 100:
        security_audit_log.pop(0)
    
    print(f"[SECURITY_AUDIT] {audit_entry['action']}: {audit_entry['executor']} removed {audit_entry['target']}")
    
    await ctx.send(f"✅ {target_type} **{target_name}** has been removed from the security authorized list.\n📊 Total authorized: {len(security_authorized_ids)}/{MAX_SECURITY_AUTHORIZED_USERS}")

@bot.command(name="securitysettings")
async def securitysettings(ctx):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    embed = discord.Embed(title="Security Settings", color=discord.Color.orange())
    noavatar_status = "Enabled" if no_avatar_filter_enabled else "Disabled"
    embed.add_field(name="No-Avatar Filter", value=f"Status: {noavatar_status}\nAction: {no_avatar_action}", inline=False)
    if no_avatar_action == "timeout" and no_avatar_filter_enabled:
        embed.add_field(name="No-Avatar Timeout", value=f"{no_avatar_timeout_duration} minutes", inline=False)
    accountage_status = "Enabled" if account_age_filter_enabled else "Disabled"
    embed.add_field(name="Account Age Filter", value=f"Status: {accountage_status}", inline=False)
    if account_age_filter_enabled:
        embed.add_field(name="Minimum Account Age", value=f"{account_age_min_days} days", inline=False)
        embed.add_field(name="Account Age Action", value=f"{account_age_action}", inline=False)
        if account_age_action == "timeout":
            embed.add_field(name="Account Age Timeout", value=f"{account_age_timeout_duration} minutes", inline=False)
    if security_authorized_ids:
        ids_str = ", ".join(str(i) for i in security_authorized_ids)
    else:
        ids_str = "No authorized IDs added"
    embed.add_field(name="Security Authorized IDs", value=ids_str, inline=False)
    embed.add_field(name="Authorization Limit", value=f"{len(security_authorized_ids)}/{MAX_SECURITY_AUTHORIZED_USERS}", inline=True)
    embed.add_field(name="Audit Log Entries", value=f"{len(security_audit_log)}/100", inline=True)
    embed.add_field(name="Rate Limiting", value=f"{SECURITY_COMMAND_RATE_LIMIT} commands/{SECURITY_COMMAND_RATE_WINDOW}s", inline=True)
    await ctx.send(embed=embed)

@bot.command(name="securityaudit")
async def securityaudit(ctx, limit: int = 10):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    if limit < 1 or limit > 50:
        await ctx.send("Limit must be between 1 and 50.")
        return
    
    if not security_audit_log:
        await ctx.send("No security audit entries found.")
        return
    
    # Get last N entries
    recent_entries = security_audit_log[-limit:]
    
    embed = discord.Embed(
        title="🔍 Security Audit Log",
        description=f"Showing last {len(recent_entries)} entries",
        color=discord.Color.orange()
    )
    
    for i, entry in enumerate(reversed(recent_entries), 1):
        action_emoji = "➕" if "ADD" in entry["action"] else "➖"
        timestamp = entry["timestamp"][:19].replace("T", " ")  # Format: YYYY-MM-DD HH:MM:SS
        
        embed.add_field(
            name=f"{action_emoji} #{i} - {entry['action']}",
            value=f"**Executor:** {entry['executor']}\n**Target:** {entry['target']}\n**Time:** {timestamp}",
            inline=False
        )
    
    await ctx.send(embed=embed)

@bot.command(name="securitysave")
async def securitysave(ctx):
    """Manuel olarak güvenlik ayarlarını kaydet"""
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    # Security: Rate limiting
    if await _handle_security_rate_limit(ctx, "securitysave"):
        return
    
    try:
        success = save_security_settings()
        if success:
            embed = discord.Embed(
                title="✅ Güvenlik Ayarları Kaydedildi",
                description=f"Tüm güvenlik ayarları `{SECURITY_SETTINGS_FILE}` dosyasına başarıyla kaydedildi.",
                color=discord.Color.green()
            )
            embed.add_field(
                name="Kaydedilen Ayarlar",
                value=(
                    f"• Yetkili ID'ler: {len(security_authorized_ids)}\n"
                    f"• No-Avatar Filter: {'Aktif' if no_avatar_filter_enabled else 'Pasif'}\n"
                    f"• Account Age Filter: {'Aktif' if account_age_filter_enabled else 'Pasif'}\n"
                    f"• Captcha Role ID: {captcha_verify_role_id or 'Ayarlanmamış'}\n"
                    f"• Regex Kuralları: {sum(len(rules) for rules in regex_settings_by_guild.values())}\n"
                    f"• Captcha Panel Metinleri: {len(captcha_panel_texts)}\n"
                    f"• Audit Log Kayıtları: {len(security_audit_log)}"
                ),
                inline=False
            )
        else:
            embed = discord.Embed(
                title="❌ Kaydetme Hatası",
                description="Güvenlik ayarları kaydedilirken bir hata oluştu. Konsol loglarını kontrol edin.",
                color=discord.Color.red()
            )
        
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"❌ Kaydetme sırasında hata: {str(e)}")

@bot.command(name="securityload")
async def securityload(ctx):
    """Manuel olarak güvenlik ayarlarını yükle"""
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    # Security: Rate limiting
    if await _handle_security_rate_limit(ctx, "securityload"):
        return
    
    try:
        success = load_security_settings()
        if success:
            embed = discord.Embed(
                title="✅ Güvenlik Ayarları Yüklendi",
                description=f"Tüm güvenlik ayarları `{SECURITY_SETTINGS_FILE}` dosyasından başarıyla yüklendi.",
                color=discord.Color.green()
            )
            embed.add_field(
                name="Yüklenen Ayarlar",
                value=(
                    f"• Yetkili ID'ler: {len(security_authorized_ids)}\n"
                    f"• No-Avatar Filter: {'Aktif' if no_avatar_filter_enabled else 'Pasif'}\n"
                    f"• Account Age Filter: {'Aktif' if account_age_filter_enabled else 'Pasif'}\n"
                    f"• Captcha Role ID: {captcha_verify_role_id or 'Ayarlanmamış'}\n"
                    f"• Regex Kuralları: {sum(len(rules) for rules in regex_settings_by_guild.values())}\n"
                    f"• Captcha Panel Metinleri: {len(captcha_panel_texts)}\n"
                    f"• Audit Log Kayıtları: {len(security_audit_log)}"
                ),
                inline=False
            )
        else:
            embed = discord.Embed(
                title="⚠️ Yükleme Uyarısı",
                description=f"Ayar dosyası `{SECURITY_SETTINGS_FILE}` bulunamadı veya yüklenirken hata oluştu. Varsayılan ayarlar kullanılıyor.",
                color=discord.Color.orange()
            )
        
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"❌ Yükleme sırasında hata: {str(e)}")

@bot.command(name="securitybackup")
async def securitybackup(ctx):
    """Güvenlik ayarlarının yedeğini oluştur"""
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    # Security: Rate limiting
    if await _handle_security_rate_limit(ctx, "securitybackup"):
        return
    
    try:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"security_settings_backup_{timestamp}.json"
        
        # Mevcut ayarları yedek dosyasına kaydet
        original_file = SECURITY_SETTINGS_FILE
        global SECURITY_SETTINGS_FILE
        SECURITY_SETTINGS_FILE = backup_filename
        
        success = save_security_settings()
        
        # Orijinal dosya adını geri yükle
        SECURITY_SETTINGS_FILE = original_file
        
        if success:
            embed = discord.Embed(
                title="✅ Güvenlik Ayarları Yedeklendi",
                description=f"Güvenlik ayarları `{backup_filename}` dosyasına yedeklendi.",
                color=discord.Color.blue()
            )
            embed.add_field(
                name="Yedek Bilgileri",
                value=(
                    f"• Dosya Adı: `{backup_filename}`\n"
                    f"• Tarih: {datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n"
                    f"• Boyut: Yaklaşık {len(str(security_authorized_ids)) + len(str(regex_settings_by_guild))} karakter"
                ),
                inline=False
            )
        else:
            embed = discord.Embed(
                title="❌ Yedekleme Hatası",
                description="Güvenlik ayarları yedeklenirken bir hata oluştu.",
                color=discord.Color.red()
            )
        
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"❌ Yedekleme sırasında hata: {str(e)}")

@bot.command(name="securityhelp")
async def securityhelp(ctx):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    help_text = (
        "**Security Commands Help Menu**\n\n"
        "1. **!noavatarfilter on [mode] [duration] / off**\n"
        "   - Description: Checks new members for an avatar. Mode options: `ban`, `kick`, `timeout`.\n"
        "   - Example: `!noavatarfilter on timeout 60` → Applies a 60-minute timeout to users without an avatar.\n\n"
        "2. **!accountagefilter on <min_days> <mode> [duration] / off**\n"
        "   - Description: Checks new members for minimum account age. Mode options: `ban`, `kick`, `timeout`.\n"
        "   - Example: `!accountagefilter on 7 timeout 60` → Applies a 60-minute timeout to accounts younger than 7 days.\n\n"
        "3. **!securityauthorizedadd <id>**\n"
        "   - Description: Authorizes the specified user or role ID for security commands.\n\n"
        "4. **!securityauthorizedremove <id>**\n"
        "   - Description: Removes the specified user or role ID from the security authorized list.\n\n"
        "5. **!securitysettings**\n"
        "   - Description: Displays current security settings (filter statuses, actions, timeout durations, etc.).\n\n"
        "6. **!regex <regexsettingsname> <regex>**\n"
        "   - Description: Defines/updates a regex rule with the given name. Supports `/pattern/flags` or `pattern --flags imsx`. If the advanced `regex` engine is installed it is used; otherwise Python's built-in `re` is used.\n\n"
        "7. **!setregexsettings <regexsettingsname> <channels>**\n"
        "   - Description: Assigns which channels the regex rule applies to. You can specify multiple channels by ID or #mention.\n"
        "   - Also supported: `!setregexsettings <name> allchannel notchannel <channels_to_exclude>` → apply to all text channels except the ones listed after `notchannel`.\n\n"
        "8. **!setregexexempt <regexsettingsname> users|roles <targets>**\n"
        "   - Description: Sets users or roles exempt from the rule.\n\n"
        "9. **!regexsettings [regexsettingsname]**\n"
        "   - Description: Shows active regex rules and their details (channels and exemptions). Provide a name to see only that rule.\n\n"
        "10. **!delregexsettings <regexsettingsname>**\n"
        "   - Description: Deletes the specified regex setting from this server.\n\n"
        "11. **!setverifyrole <role_id|@role>**\n"
        "   - Description: Sets the role to be assigned after successful CAPTCHA verification.\n"
        "   - Example: `!setverifyrole @Verified` → Sets the Verified role as the verification reward.\n\n"
        "12. **!sendverifypanel [#channel|channel_id]**\n"
        "   - Description: Sends a verification panel with CAPTCHA button to the specified channel (or current channel).\n"
        "   - Example: `!sendverifypanel #verification` → Sends verification panel to the verification channel.\n\n"
        "13. **!setverifypaneltext <title|description|image> <text|url>**\n"
        "   - Description: Customizes the verification panel title, description text, or image.\n"
        "   - Examples: `!setverifypaneltext title Welcome to Our Server` → Changes panel title.\n"
        "   - `!setverifypaneltext image https://example.com/logo.png` → Adds panel image.\n\n"
        "14. **!showverifypaneltext**\n"
        "   - Description: Shows the current verification panel text settings.\n\n"
        "15. **!resetverifypaneltext**\n"
        "   - Description: Resets verification panel text to default values.\n\n"
        "16. **!setbotdetection <rule_name> <settings>**\n"
        "   - Description: Creates/updates bot detection rule with AND/OR logic for flexible combinations.\n"
        "   - Parameters: `consecutive=<num> total_same=<num> consecutive_noreply=<num> total_noreply=<num> time=<seconds> message_logic=<and|or> <action> [timeout_duration] [notification_channel] [account_age_days] [check_avatar] [overall_logic=and|or]`\n"
        "   - **Parameter Details:**\n"
        "     • `consecutive=<num>`: Consecutive identical messages limit (0=disabled). Detects same message sent X times in a row.\n"
        "     • `total_same=<num>`: Total identical messages limit within time window (0=disabled). Counts same message sent X times total.\n"
        "     • `consecutive_noreply=<num>`: Consecutive messages without replies/mentions limit (0=disabled). Detects X messages in a row without interaction.\n"
        "     • `total_noreply=<num>`: Total messages without replies within time window (0=disabled). Counts X non-interactive messages total.\n"
        "     • `time=<seconds>`: Time window for analysis (1-2592000 seconds). Common: 300=5min, 3600=1hour, 86400=24hours.\n"
        "     • `message_logic=<and|or>`: How to combine message criteria. OR=any criterion triggers, AND=all criteria must be met.\n"
        "     • `<action>`: Action to take - notify, timeout, kick, ban.\n"
        "     • `[timeout_duration]`: Minutes for timeout action (required if action=timeout, use 'none' for other actions).\n"
        "     • `[notification_channel]`: Channel for notifications (#channel or 'none' to disable notifications).\n"
        "     • `[account_age_days]`: Maximum account age in days for detection (optional).\n"
        "     • `[check_avatar]`: Check for missing avatar - true/false (optional).\n"
        "     • `[overall_logic=and|or]`: How to combine message criteria with account criteria. OR=either group triggers, AND=both groups required.\n"
        "   - Example: `!setbotdetection spam_rule consecutive=3 total_same=5 consecutive_noreply=3 total_noreply=8 time=86400 message_logic=or timeout 60 #mod-log none false overall_logic=or` → Message OR + Overall OR\n"
        "   - Example: `!setbotdetection strict_rule consecutive=2 total_same=3 consecutive_noreply=2 total_noreply=5 time=300 message_logic=and ban none #mod-log 7 true overall_logic=and` → Message AND + Overall AND\n"
        "   - Example: `!setbotdetection mixed_rule consecutive=0 total_same=10 consecutive_noreply=0 total_noreply=15 time=300 message_logic=or notify none #mod-log 7 true overall_logic=or` → Total controls\n\n"
        "17. **!setbotdetectionchannels <rule_name> <channels>**\n"
        "   - Description: Sets channels to monitor for bot detection rule.\n"
        "   - Example: `!setbotdetectionchannels spam_rule #general #chat`\n\n"
        "18. **!setbotdetectionexempt <rule_name> users|roles <targets>**\n"
        "   - Description: Sets exempt users/roles for bot detection rule.\n"
        "   - Example: `!setbotdetectionexempt spam_rule users @alice @bob`\n\n"
        "19. **!botdetections**\n"
        "   - Description: Lists all bot detection rules.\n\n"
        "20. **!botdetectionsettings [rule_name]**\n"
        "   - Description: Shows bot detection settings (specific rule or all).\n\n"
        "21. **!deletebotdetections <rule_name>**\n"
        "   - Description: Deletes the specified bot detection rule.\n\n"
        "22. **!securitysave**\n"
        "   - Description: Manuel olarak tüm güvenlik ayarlarını JSON dosyasına kaydet.\n"
        "   - Example: `!securitysave` → Ayarları security_settings.json dosyasına kaydeder.\n\n"
        "23. **!securityload**\n"
        "   - Description: Manuel olarak güvenlik ayarlarını JSON dosyasından yükle.\n"
        "   - Example: `!securityload` → security_settings.json dosyasından ayarları yükler.\n\n"
        "24. **!securitybackup**\n"
        "   - Description: Güvenlik ayarlarının tarihli yedeğini oluştur.\n"
        "   - Example: `!securitybackup` → security_settings_backup_20231201_143022.json şeklinde yedek oluşturur.\n\n"
        "25. **!securityhelp**\n"
        "   - Description: Shows this help menu.\n\n"
        "## 🤖 Bot Detection System Detailed Guide\n\n"
        "**Detection Criteria (6 Types):**\n"
        "1. **Consecutive Identical Messages (consecutive=X):** Same message sent X times in a row. Resets when different message is sent.\n"
        "   Example: User sends 'gm' 5 times consecutively → Detected if consecutive=5\n"
        "2. **Total Same Messages (total_same=X):** Same message sent X times total within time window (not necessarily consecutive).\n"
        "   Example: User sends 'hello' 10 times over 1 hour with other messages in between → Detected if total_same=10\n"
        "3. **Consecutive No-Reply Messages (consecutive_noreply=X):** X messages in a row without replies/mentions. Resets when reply is sent.\n"
        "   Example: User sends 5 messages without @mentions or Discord replies → Detected if consecutive_noreply=5\n"
        "4. **Total No-Reply Messages (total_noreply=X):** X messages total without replies within time window.\n"
        "   Example: User sends 15 messages in 24h, none with @mentions or replies → Detected if total_noreply=15\n"
        "5. **Account Age (account_age_days=X):** Account created within X days.\n"
        "   Example: 3-day old account → Detected if account_age_days=7\n"
        "6. **No Avatar (check_avatar=true):** User has no custom profile picture (uses Discord default).\n\n"
        "**Two-Level Logic System:**\n"
        "• **Message Logic (message_logic=and|or):** How to combine the 4 message criteria\n"
        "  - OR (default): Any message criterion triggers → More sensitive\n"
        "  - AND: All enabled message criteria must be met → More strict\n"
        "• **Overall Logic (overall_logic=and|or):** How to combine message group with account group\n"
        "  - OR (default): Message criteria OR account criteria → More flexible\n"
        "  - AND: Message criteria AND account criteria → Most strict\n\n"
        "**Actions:** `notify` (log only), `timeout` (temporary mute), `kick` (remove from server), `ban` (permanent ban)\n\n"
        "**Reply Detection (What counts as interaction):**\n"
        "• Discord's native reply feature (most reliable)\n"
        "• @user mentions, @everyone/@here mentions, @role mentions\n"
        "• Does NOT count: Messages containing words 'reply' or 'respond'\n\n"
        "**Time Window:** 1 second to 30 days (2,592,000 seconds)\n"
        "• Common values: 300=5min, 1800=30min, 3600=1hour, 86400=24hours, 604800=7days\n\n"
        "**Parameter Order & Examples:**\n"
        "Command format: `!setbotdetection <rule> consecutive=X total_same=X consecutive_noreply=X total_noreply=X time=X message_logic=or|and <action> [timeout_mins] [#channel] [account_age] [avatar_check] [overall_logic]`\n\n"
        "**Parameter Position Guide:**\n"
        "1. Rule name and detection parameters (consecutive, total_same, etc.)\n"
        "2. Action (notify, timeout, kick, ban)\n"
        "3. Timeout duration (only for timeout action, use 'none' for others)\n"
        "4. Notification channel (#channel or 'none')\n"
        "5. Account age limit in days (number or 'none')\n"
        "6. Avatar check (true/false)\n"
        "7. Overall logic (and/or)\n\n"
        "**Examples with clear parameter positions:**\n"
        "• `consecutive=3 total_same=5 time=86400 message_logic=or timeout 60 #mod-log none false or` → timeout=60min, channel=#mod-log, no account age check\n"
        "• `consecutive=2 total_same=3 time=300 message_logic=and ban none #security-log 7 true and` → ban action, channel=#security-log, 7-day account check\n"
        "• `consecutive=0 total_same=10 time=604800 message_logic=or kick none none none false or` → kick action, no notifications, no account checks\n"
        "• `consecutive=0 total_same=0 time=300 message_logic=or notify none #new-users 14 true or` → notify only, channel=#new-users, 14-day + avatar check\n\n"
    )
    # Split into chunks to respect Discord 2000-char message limit
    parts = []
    buffer = []
    current_len = 0
    for para in help_text.split("\n\n"):
        block = para + "\n\n"
        if current_len + len(block) > 1900:
            if buffer:
                parts.append("".join(buffer).rstrip())
                buffer = [block]
                current_len = len(block)
            else:
                # Hard-split if single block is too long
                for i in range(0, len(block), 1900):
                    parts.append(block[i:i+1900])
                buffer = []
                current_len = 0
        else:
            buffer.append(block)
            current_len += len(block)
    if buffer:
        parts.append("".join(buffer).rstrip())
    for part in parts:
        await ctx.send(part)

# ---------------- CAPTCHA Verification ----------------

def _check_captcha_rate_limit(user_id: int) -> bool:
    """Check if user is within rate limit for captcha requests"""
    current_time = time.time()
    user_requests = captcha_rate_limits[user_id]
    
    # Remove old requests outside the window
    user_requests[:] = [req_time for req_time in user_requests if current_time - req_time < CAPTCHA_RATE_WINDOW]
    
    # Check if user has exceeded rate limit
    if len(user_requests) >= CAPTCHA_RATE_LIMIT:
        return False
    
    return True

def _add_captcha_rate_limit_request(user_id: int):
    """Add a request to the rate limit tracker"""
    current_time = time.time()
    captcha_rate_limits[user_id].append(current_time)


def _generate_captcha_code(length: int = 6) -> str:
    # Avoid ambiguous characters like 0/O and 1/I
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(random.choice(alphabet) for _ in range(length))


def _create_ascii_captcha(code: str) -> str:
    """Creates ASCII art style captcha"""
    ascii_chars = {
        'A': [
            " ███ ",
            "█████",
            "█   █"
        ],
        'B': [
            "████ ",
            "████ ",
            "████ "
        ],
        'C': [
            " ████",
            "█    ",
            " ████"
        ],
        'D': [
            "████ ",
            "█   █",
            "████ "
        ],
        'E': [
            "█████",
            "████ ",
            "█████"
        ],
        'F': [
            "█████",
            "████ ",
            "█    "
        ],
        'G': [
            " ████",
            "█  ██",
            " ████"
        ],
        'H': [
            "█   █",
            "█████",
            "█   █"
        ],
        'J': [
            "   ██",
            "   ██",
            "████ "
        ],
        'K': [
            "█  ██",
            "███  ",
            "█  ██"
        ],
        'L': [
            "█    ",
            "█    ",
            "█████"
        ],
        'M': [
            "█████",
            "█ █ █",
            "█   █"
        ],
        'N': [
            "█   █",
            "██  █",
            "█  ██"
        ],
        'P': [
            "████ ",
            "████ ",
            "█    "
        ],
        'Q': [
            " ███ ",
            "█   █",
            " ████"
        ],
        'R': [
            "████ ",
            "████ ",
            "█  ██"
        ],
        'S': [
            " ████",
            " ███ ",
            "████ "
        ],
        'T': [
            "█████",
            "  █  ",
            "  █  "
        ],
        'U': [
            "█   █",
            "█   █",
            " ███ "
        ],
        'V': [
            "█   █",
            " █ █ ",
            "  █  "
        ],
        'W': [
            "█   █",
            "█ █ █",
            " ███ "
        ],
        'X': [
            "█   █",
            " ███ ",
            "█   █"
        ],
        'Y': [
            "█   █",
            " ███ ",
            "  █  "
        ],
        'Z': [
            "█████",
            "  ██ ",
            "█████"
        ],
        '2': [
            "█████",
            "    █",
            "█████"
        ],
        '3': [
            "█████",
            " ████",
            "█████"
        ],
        '4': [
            "█   █",
            "█████",
            "    █"
        ],
        '5': [
            "█████",
            "████ ",
            "█████"
        ],
        '6': [
            "█████",
            "█████",
            "█████"
        ],
        '7': [
            "█████",
            "    █",
            "    █"
        ],
        '8': [
            "█████",
            "█████",
            "█████"
        ],
        '9': [
            "█████",
            "█████",
            "█████"
        ]
    }
    
    # Get ASCII art for each character
    lines = ["", "", ""]
    for char in code:
        if char in ascii_chars:
            art = ascii_chars[char]
            for i in range(3):
                lines[i] += art[i] + " "
        else:
            # Simple representation for unknown characters
            lines[0] += f" {char}  "
            lines[1] += f" {char}  "
            lines[2] += f" {char}  "
    
    return "\n".join(lines)


def _create_text_image(code: str) -> bytes:
    """Creates simple text image"""
    width, height = 300, 100
    # Light background
    bg_color = (245, 245, 245)
    text_color = (30, 30, 30)
    
    image = Image.new("RGB", (width, height), bg_color)
    draw = ImageDraw.Draw(image)
    
    # Font loading
    font = None
    possible_fonts = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for fp in possible_fonts:
        try:
            font = ImageFont.truetype(fp, 48)
            break
        except Exception:
            pass
    if font is None:
        font = ImageFont.load_default()
    
    # Center text
    try:
        bbox = draw.textbbox((0, 0), code, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
    except AttributeError:
        # Old PIL version
        text_width, text_height = draw.textsize(code, font=font)
    
    x = (width - text_width) // 2
    y = (height - text_height) // 2
    
    # Draw text
    draw.text((x, y), code, font=font, fill=text_color)
    
    # Add light noise
    for _ in range(50):
        x_noise = random.randint(0, width - 1)
        y_noise = random.randint(0, height - 1)
        image.putpixel((x_noise, y_noise), (
            random.randint(200, 240),
            random.randint(200, 240), 
            random.randint(200, 240)
        ))
    
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


class CaptchaModal(discord.ui.Modal):
    def __init__(self, expected_code: str, verify_role_id: int, user_id: int = None, show_code_hint: bool = False):
        super().__init__(title="Captcha Verification")
        self.expected_code = expected_code
        self.verify_role_id = verify_role_id
        self.user_id = user_id
        self.answer_input = discord.ui.TextInput(
            label=(f"Enter code: {expected_code}" if show_code_hint else "Enter code"),
            placeholder="Type the code here",
            min_length=1,
            max_length=12,
            required=True,
        )
        self.add_item(self.answer_input)

    async def on_submit(self, interaction: discord.Interaction):
        provided = (self.answer_input.value or "").strip()
        if provided != self.expected_code:
            await interaction.response.send_message(
                "Incorrect code. Please click the verification button again to retry.",
                ephemeral=True,
            )
            return

        guild = interaction.guild
        if guild is None:
            await interaction.response.send_message(
                "This action can only be performed within a server.", ephemeral=True
            )
            return

        role = guild.get_role(self.verify_role_id)
        if role is None:
            await interaction.response.send_message(
                "Verification role not found. Please contact an administrator.",
                ephemeral=True,
            )
            return

        # Ensure we have a Member object
        member = interaction.user
        if not isinstance(member, discord.Member):
            try:
                member = await guild.fetch_member(interaction.user.id)
            except Exception:
                member = None

        if member is None:
            await interaction.response.send_message(
                "Unable to retrieve member information.", ephemeral=True
            )
            return

        # If already verified
        if any(r.id == role.id for r in getattr(member, "roles", [])):
            await interaction.response.send_message(
                "You are already verified.", ephemeral=True
            )
            return

        try:
            await member.add_roles(role, reason="Captcha verified")
        except discord.Forbidden:
            await interaction.response.send_message(
                "Unable to assign role: Bot lacks permissions or role hierarchy prevents this action.",
                ephemeral=True,
            )
            return
        except Exception:
            await interaction.response.send_message(
                "An error occurred while assigning the role.", ephemeral=True
            )
            return

        await interaction.response.send_message(
            f"Success! {role.mention} role has been assigned.", ephemeral=True
        )
        
        # Clean up session after successful verification
        if self.user_id:
            active_captcha_sessions.discard(self.user_id)
            # Security: Don't log sensitive verification details
            print(f"[captcha] User verification completed successfully (ID: {self.user_id})")


class CaptchaVerifyView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(
        label="Verify",
        style=discord.ButtonStyle.success,
        custom_id="captcha_verify_button",
    )
    async def verify_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        # This method is now handled by the on_interaction event handler
        # to prevent double acknowledgment issues
        pass


class CaptchaCodeEntryView(discord.ui.View):
    def __init__(self, expected_code: str, verify_role_id: int, user_id: int):
        super().__init__(timeout=180)
        self.expected_code = expected_code
        self.verify_role_id = verify_role_id
        self.user_id = user_id

    @discord.ui.button(label="Enter Code", style=discord.ButtonStyle.primary, custom_id="captcha_enter_code")
    async def enter_code(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        # Only allow the original user to use this button
        if interaction.user.id != self.user_id:
            await interaction.response.send_message(
                "This captcha is not for you.", ephemeral=True
            )
            return
            
        await interaction.response.send_modal(CaptchaModal(self.expected_code, self.verify_role_id, self.user_id))

    async def on_timeout(self):
        # Clean up session when view times out
        active_captcha_sessions.discard(self.user_id)
        print(f"[captcha] Session timeout for user {self.user_id}")


@bot.event
async def on_ready():
    # Load security settings on startup
    load_security_settings()
    
    # Load persistent data (match lastguard)
    _load_bot_data()
    # Start periodic data saving task every 5 minutes (match lastguard)
    async def _periodic_data_save():
        while True:
            try:
                await asyncio.sleep(300)
                _save_bot_data()
                save_security_settings()  # Güvenlik ayarlarını da periyodik kaydet
                print("[persistence] Periodic data save completed")
            except Exception as e:
                print(f"[persistence] Error in periodic save: {e}")
    asyncio.create_task(_periodic_data_save())
    print("[persistence] Periodic data saving started (every 5 minutes)")
    # Register persistent view so button keeps working after restart
    try:
        bot.add_view(CaptchaVerifyView())
    except Exception:
        pass
    print(f"Logged in as {bot.user} (ID: {getattr(bot.user, 'id', '-')})")


@bot.command(name="setverifyrole")
async def setverifyrole(ctx, role_identifier: str):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    # Security: Rate limiting
    if await _handle_security_rate_limit(ctx, "setverifyrole"):
        return
    global captcha_verify_role_id

    raw = role_identifier.strip()
    if raw.startswith("<@&") and raw.endswith(">"):
        raw = raw[3:-1]
    try:
        rid = int(raw)
    except ValueError:
        await ctx.send("Please enter a valid role ID or role mention.")
        return
    role = ctx.guild.get_role(rid)
    if role is None:
        await ctx.send("No role found with this ID.")
        return
    captcha_verify_role_id = rid
    # Auto-save settings
    auto_save_security_settings()
    await ctx.send(f"Verification role set: {role.mention} ({rid})")


# ---------------- Bot Detection Commands ----------------

@bot.command(name="setbotdetection")
async def setbotdetection(ctx, rule_name: str, *, settings_text: str = None):
    """
    Bot algılama kuralını yapılandırır
    Kullanım: !setbotdetection <kural_adı> consecutive=<sayı> total_same=<sayı> consecutive_noreply=<sayı> total_noreply=<sayı> time=<saniye> message_logic=<and|or> <action> [timeout_duration] [notification_channel] [account_age_days] [check_avatar] [overall_logic=and|or]
    """
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    if await _handle_security_rate_limit(ctx, "setbotdetection"):
        return

    guild_id = ctx.guild.id
    rule_name = rule_name.strip().lower()

    if not settings_text:
        await ctx.send(
            "Bot algılama kuralı ayarlarını belirtiniz.\n"
            "Kullanım: `!setbotdetection <kural_adı> consecutive=<sayı> total_same=<sayı> consecutive_noreply=<sayı> total_noreply=<sayı> time=<saniye> message_logic=<and|or> <action> [timeout_duration] [notification_channel] [account_age_days] [check_avatar] [overall_logic=and|or]`"
        )
        return

    parts = settings_text.split()

    repeated_count = 0
    total_same_count = 0
    consecutive_count = 0
    total_consecutive_count = 0
    time_window = 300
    message_logic_operator = "or"
    action = None

    action_index = -1
    for i, part in enumerate(parts):
        if "=" not in part and part.lower() in ["notify", "timeout", "kick", "ban"]:
            action = part.lower()
            action_index = i
            break
    if not action:
        await ctx.send("İşlem belirtilmedi. Seçenekler: `notify`, `timeout`, `kick`, `ban`")
        return

    try:
        for i, part in enumerate(parts):
            if i == action_index:
                break
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.lower()
                if key == "message_logic":
                    value_norm = value.lower()
                    if value_norm in ["and", "ve"]:
                        message_logic_operator = "and"
                    elif value_norm in ["or", "veya"]:
                        message_logic_operator = "or"
                    else:
                        await ctx.send("message_logic için 'and' veya 'or' belirtin.")
                        return
                    continue
                value_int = int(value)
                if key == "consecutive":
                    repeated_count = value_int
                elif key == "total_same":
                    total_same_count = value_int
                elif key == "consecutive_noreply":
                    consecutive_count = value_int
                elif key == "total_noreply":
                    total_consecutive_count = value_int
                elif key == "time":
                    time_window = value_int
                else:
                    await ctx.send("Bilinmeyen parametre. Geçerli: consecutive, total_same, consecutive_noreply, total_noreply, time, message_logic")
                    return

        if (
            repeated_count < 0
            or total_same_count < 0
            or consecutive_count < 0
            or total_consecutive_count < 0
            or time_window < 1
        ):
            await ctx.send("Tekrar ve ardışık sayıları 0 veya üzeri, zaman penceresi 1'den büyük olmalıdır.")
            return
        if time_window > 2592000:
            await ctx.send("Zaman penceresi maksimum 30 gün (2592000 saniye) olabilir.")
            return
        if action not in ["notify", "timeout", "kick", "ban"]:
            await ctx.send("Geçersiz işlem. Seçenekler: `notify`, `timeout`, `kick`, `ban`")
            return

        timeout_duration = 60
        notification_channel_id = None
        max_account_age_days = None
        check_no_avatar = False

        param_idx = action_index + 1
        if len(parts) > param_idx:
            if action == "timeout":
                if parts[param_idx].lower() != "none":
                    try:
                        timeout_duration = int(parts[param_idx])
                        if timeout_duration < 1:
                            await ctx.send("Timeout süresi 1 dakikadan az olamaz.")
                            return
                    except ValueError:
                        await ctx.send("Geçersiz timeout süresi.")
                        return
            param_idx += 1

        if len(parts) > param_idx:
            if parts[param_idx].lower() != "none":
                channel_str = parts[param_idx]
                if channel_str.startswith("<#") and channel_str.endswith(">"):
                    channel_str = channel_str[2:-1]
                try:
                    channel_id = int(channel_str)
                    channel = ctx.guild.get_channel(channel_id)
                    if channel:
                        notification_channel_id = channel_id
                    else:
                        await ctx.send(f"Kanal bulunamadı: {channel_str}")
                        return
                except ValueError:
                    await ctx.send("Geçersiz kanal ID'si.")
                    return
            param_idx += 1

        if len(parts) > param_idx:
            try:
                max_account_age_days = int(parts[param_idx])
                if max_account_age_days < 0:
                    await ctx.send("Hesap yaşı 0 veya üzeri olmalıdır.")
                    return
            except ValueError:
                await ctx.send("Geçersiz hesap yaşı değeri.")
                return
            param_idx += 1

        if len(parts) > param_idx:
            avatar_param = parts[param_idx].lower()
            if avatar_param in ["true", "1", "yes", "evet"]:
                check_no_avatar = True
            elif avatar_param in ["false", "0", "no", "hayır"]:
                check_no_avatar = False
            else:
                await ctx.send("Avatar kontrolü için true/false belirtin.")
                return
            param_idx += 1

        logic_operator = "or"
        if len(parts) > param_idx:
            logic_param = parts[param_idx]
            if logic_param.startswith("overall_logic="):
                overall_logic_value = logic_param.split("=")[1].lower()
                if overall_logic_value in ["and", "ve"]:
                    logic_operator = "and"
                elif overall_logic_value in ["or", "veya"]:
                    logic_operator = "or"
                else:
                    await ctx.send("overall_logic için 'and' veya 'or' belirtin.")
                    return
            else:
                logic_param_l = logic_param.lower()
                if logic_param_l in ["and", "ve"]:
                    logic_operator = "and"
                elif logic_param_l in ["or", "veya"]:
                    logic_operator = "or"
                else:
                    await ctx.send("Mantık operatörü için 'and' veya 'or' belirtin.")
                    return

        if guild_id not in bot_detection_rules:
            bot_detection_rules[guild_id] = {}

        rule_settings = {
            "enabled": True,
            "channels": set(),
            "repeated_message_count": repeated_count,
            "total_same_message_count": total_same_count,
            "consecutive_message_count": consecutive_count,
            "total_consecutive_message_count": total_consecutive_count,
            "time_window": time_window,
            "action": action,
            "timeout_duration": timeout_duration,
            "notification_channel": notification_channel_id,
            "exempt_users": set(),
            "exempt_roles": set(),
            "check_account_age": max_account_age_days is not None,
            "max_account_age_days": max_account_age_days or 7,
            "check_no_avatar": check_no_avatar,
            "message_logic_operator": message_logic_operator,
            "logic_operator": logic_operator,
        }

        bot_detection_rules[guild_id][rule_name] = rule_settings

        response = f"✅ Bot algılama kuralı oluşturuldu/güncellendi: **{rule_name}**\n"
        if repeated_count > 0:
            response += f"• Tekrar mesaj limiti: {repeated_count} (ard arda)\n"
        if total_same_count > 0:
            response += f"• Toplam aynı mesaj limiti: {total_same_count} (toplamda)\n"
        if consecutive_count > 0:
            response += f"• Ardışık mesaj limiti: {consecutive_count} (ard arda)\n"
        if total_consecutive_count > 0:
            response += f"• Toplam yanıtsız mesaj limiti: {total_consecutive_count} (toplamda)\n"
        if repeated_count > 0 or total_same_count > 0 or consecutive_count > 0 or total_consecutive_count > 0:
            response += f"• Zaman penceresi: {time_window} saniye\n"
        if max_account_age_days is not None:
            response += f"• Maksimum hesap yaşı: {max_account_age_days} gün\n"
        if check_no_avatar:
            response += f"• Avatar kontrolü: Etkin\n"
        response += f"• İşlem: {action}\n"
        if repeated_count > 0 or total_same_count > 0 or consecutive_count > 0 or total_consecutive_count > 0:
            response += f"• Mesaj Mantığı: {message_logic_operator.upper()}\n"
        response += f"• Genel Mantık: {logic_operator.upper()}"
        if action == "timeout":
            response += f"\n• Timeout süresi: {timeout_duration} dakika"
        if notification_channel_id:
            response += f"\n• Bildirim kanalı: <#{notification_channel_id}>"
        has_detection = (
            repeated_count > 0
            or consecutive_count > 0
            or max_account_age_days is not None
            or check_no_avatar
        )
        if not has_detection:
            response += "\n\n⚠️ Uyarı: Hiçbir algılama yöntemi etkin değil!"
        elif repeated_count > 0 or consecutive_count > 0:
            response += f"\n\n⚠️ Not: Mesaj tabanlı algılama için `!setbotdetectionchannels {rule_name}` ile kanalları belirleyin."
        await ctx.send(response)
    except ValueError:
        await ctx.send("Geçersiz sayısal değerler. Lütfen geçerli sayılar girin.")
        return


@bot.command(name="setbotdetectionchannels")
async def setbotdetectionchannels(ctx, rule_name: str, *, channels: str):
    """Set channels to monitor for bot detection rule"""
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return

    guild_id = ctx.guild.id
    rule_name = rule_name.strip().lower()

    if guild_id not in bot_detection_rules or rule_name not in bot_detection_rules[guild_id]:
        await ctx.send(f"Önce '{rule_name}' kuralını oluşturun: `!setbotdetection {rule_name} ...`")
        return

    tokens = channels.replace(",", " ").split()
    lower_tokens = [t.lower() for t in tokens]
    selected: set[int] = set()
    invalid: list[str] = []

    def _parse_channel_token(token: str):
        raw = token.strip()
        if raw.startswith("<#") and raw.endswith(">"):
            raw = raw[2:-1]
        try:
            cid_local = int(raw)
        except ValueError:
            return None
        channel_local = ctx.guild.get_channel(cid_local)
        if channel_local is None:
            return None
        return cid_local

    if "allchannel" in lower_tokens:
        for ch in ctx.guild.text_channels:
            selected.add(ch.id)
        if "notchannel" in lower_tokens:
            idx = lower_tokens.index("notchannel")
            exclude_tokens = tokens[idx + 1 :]
            if exclude_tokens:
                exclude_ids: set[int] = set()
                for tok in exclude_tokens:
                    cid = _parse_channel_token(tok)
                    if cid is None:
                        invalid.append(tok)
                    else:
                        exclude_ids.add(cid)
                selected -= exclude_ids
    else:
        if "notchannel" in lower_tokens:
            await ctx.send("`notchannel` yalnızca `allchannel` ile birlikte kullanılabilir.")
            return
        for tok in tokens:
            cid = _parse_channel_token(tok)
            if cid is None:
                invalid.append(tok)
                continue
            selected.add(cid)

    if not selected:
        await ctx.send(
            f"Lütfen geçerli kanallar belirtin. Örnekler: `!setbotdetectionchannels {rule_name} #general #chat` veya `!setbotdetectionchannels {rule_name} allchannel notchannel #log #mod`"
        )
        return

    bot_detection_rules[guild_id][rule_name]["channels"] = selected
    ch_mentions = ", ".join(f"<#{cid}>" for cid in selected)
    msg = f"**{rule_name}** kuralı için bot algılama kanalları güncellendi: {ch_mentions}"
    if invalid:
        msg += f"\nGeçersiz/Yok sayılan: {' '.join(invalid)}"
    await ctx.send(msg)


@bot.command(name="setbotdetectionexempt")
async def setbotdetectionexempt(ctx, rule_name: str, kind: str, *, targets: str):
    """Set exemptions for bot detection rule"""
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return

    guild_id = ctx.guild.id
    rule_name = rule_name.strip().lower()

    if guild_id not in bot_detection_rules or rule_name not in bot_detection_rules[guild_id]:
        await ctx.send(f"Önce '{rule_name}' kuralını oluşturun: `!setbotdetection {rule_name} ...`")
        return

    kind_l = kind.strip().lower()
    if kind_l not in ("users", "roles"):
        await ctx.send("Lütfen bir tür belirtin: `users` veya `roles`. Örnek: `!setbotdetectionexempt users @user1 @user2`")
        return

    tokens = targets.replace(",", " ").split()
    selected: set[int] = set()
    invalid = []

    for tok in tokens:
        raw = tok.strip()
        if kind_l == "roles":
            if raw.startswith("<@&") and raw.endswith(">"):
                raw = raw[3:-1]
        else:
            if raw.startswith("<@!") and raw.endswith(">"):
                raw = raw[3:-1]
            elif raw.startswith("<@") and raw.endswith(">"):
                raw = raw[2:-1]
        try:
            _id = int(raw)
        except ValueError:
            invalid.append(tok)
            continue
        if kind_l == "roles":
            role = ctx.guild.get_role(_id)
            if role is None:
                invalid.append(tok)
                continue
        else:
            member = ctx.guild.get_member(_id)
            if member is None:
                invalid.append(tok)
                continue
        selected.add(_id)

    if not selected:
        await ctx.send(f"Lütfen geçerli hedefler belirtin. Örnekler:\n- `!setbotdetectionexempt {rule_name} users @alice @bob`\n- `!setbotdetectionexempt {rule_name} roles @Admin 123456789012345678`")
        return

    if kind_l == "roles":
        bot_detection_rules[guild_id][rule_name]["exempt_roles"] = selected
        mentions = ", ".join(f"<@&{i}>" for i in selected)
        msg = f"**{rule_name}** kuralı için muaf roller güncellendi: {mentions}"
    else:
        bot_detection_rules[guild_id][rule_name]["exempt_users"] = selected
        mentions = ", ".join(f"<@{i}>" for i in selected)
        msg = f"**{rule_name}** kuralı için muaf kullanıcılar güncellendi: {mentions}"

    if invalid:
        msg += f"\nGeçersiz/Yok sayılan: {' '.join(invalid)}"
    await ctx.send(msg)


@bot.command(name="botdetectionsettings")
async def botdetectionsettings(ctx, rule_name: str = None):
    """Show bot detection settings for a specific rule or all rules"""
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return

    guild_id = ctx.guild.id
    guild_rules = bot_detection_rules.get(guild_id)
    if not guild_rules:
        await ctx.send("Bu sunucuda bot algılama kuralları tanımlanmamış.")
        return

    def _mentions_list(ids: set[int], kind: str) -> str:
        if not ids:
            return "Yok"
        if kind == "channel":
            return ", ".join(f"<#{i}>" for i in ids)
        if kind == "user":
            return ", ".join(f"<@{i}>" for i in ids)
        if kind == "role":
            return ", ".join(f"<@&{i}>" for i in ids)
        return "Yok"

    if rule_name:
        rule_name = rule_name.strip().lower()
        if rule_name not in guild_rules:
            await ctx.send(f"'{rule_name}' adında bir kural bulunamadı.")
            return
        settings = guild_rules[rule_name]
        embed = discord.Embed(title=f"🤖 Bot Detection Rule: {rule_name}", color=discord.Color.blue())
        status = "Enabled" if settings.get("enabled", False) else "Disabled"
        embed.add_field(name="Status", value=status, inline=True)
        repeated_count = settings.get("repeated_message_count", 0)
        total_same_count = settings.get("total_same_message_count", 0)
        consecutive_count = settings.get("consecutive_message_count", 0)
        total_consecutive_count = settings.get("total_consecutive_message_count", 0)
        if repeated_count > 0:
            embed.add_field(name="Repeated Message Limit", value=f"{repeated_count} (consecutive)", inline=True)
        if total_same_count > 0:
            embed.add_field(name="Total Same Message Limit", value=f"{total_same_count} (total)", inline=True)
        if consecutive_count > 0:
            embed.add_field(name="Consecutive Message Limit", value=f"{consecutive_count} (consecutive)", inline=True)
        if total_consecutive_count > 0:
            embed.add_field(name="Total No-Reply Message Limit", value=f"{total_consecutive_count} (total)", inline=True)
        if repeated_count > 0 or total_same_count > 0 or consecutive_count > 0 or total_consecutive_count > 0:
            embed.add_field(name="Time Window", value=f"{settings.get('time_window', 300)} seconds", inline=True)
        if settings.get("check_account_age", False):
            embed.add_field(name="Account Age Check", value=f"≤ {settings.get('max_account_age_days', 7)} days", inline=True)
        if settings.get("check_no_avatar", False):
            embed.add_field(name="Avatar Check", value="Enabled", inline=True)
        embed.add_field(name="Action", value=settings.get("action", "notify").title(), inline=True)
        message_logic_op = settings.get("message_logic_operator", "or").upper()
        if repeated_count > 0 or total_same_count > 0 or consecutive_count > 0 or total_consecutive_count > 0:
            embed.add_field(name="Message Logic", value=message_logic_op, inline=True)
        logic_op = settings.get("logic_operator", "or").upper()
        embed.add_field(name="Overall Logic", value=logic_op, inline=True)
        if settings.get("action") == "timeout":
            embed.add_field(name="Timeout Duration", value=f"{settings.get('timeout_duration', 60)} minutes", inline=True)
        channels = settings.get("channels", set())
        if repeated_count > 0 or total_same_count > 0 or consecutive_count > 0 or total_consecutive_count > 0:
            embed.add_field(name="Monitored Channels", value=_mentions_list(channels, "channel"), inline=False)
        notification_channel_id = settings.get("notification_channel")
        if notification_channel_id:
            embed.add_field(name="Notification Channel", value=f"<#{notification_channel_id}>", inline=False)
        else:
            embed.add_field(name="Notification Channel", value="Not set", inline=False)
        exempt_users = settings.get("exempt_users", set())
        exempt_roles = settings.get("exempt_roles", set())
        embed.add_field(name="Exempt Users", value=_mentions_list(exempt_users, "user"), inline=False)
        embed.add_field(name="Exempt Roles", value=_mentions_list(exempt_roles, "role"), inline=False)
        await ctx.send(embed=embed)
        return

    else:
        # Show all rules (alias behavior)
        embed = discord.Embed(title="🤖 Bot Detection Rules", color=discord.Color.blue())
        if not guild_rules:
            embed.description = "No bot detection rules defined for this server."
        else:
            for rule_name_i, settings in guild_rules.items():
                status = "✅ Enabled" if settings.get("enabled", False) else "❌ Disabled"
                channels = settings.get("channels", set())
                channel_count = len(channels)
                detection_methods = []
                if settings.get("repeated_message_count", 0) > 0:
                    detection_methods.append(f"Repeat: {settings.get('repeated_message_count')}")
                if settings.get("total_same_message_count", 0) > 0:
                    detection_methods.append(f"Total Same: {settings.get('total_same_message_count')}")
                if settings.get("consecutive_message_count", 0) > 0:
                    detection_methods.append(f"Consecutive: {settings.get('consecutive_message_count')}")
                if settings.get("total_consecutive_message_count", 0) > 0:
                    detection_methods.append(f"Total No-Reply: {settings.get('total_consecutive_message_count')}")
                if settings.get("check_account_age", False):
                    detection_methods.append(f"Age: ≤{settings.get('max_account_age_days', 7)}d")
                if settings.get("check_no_avatar", False):
                    detection_methods.append("Avatar: ❌")
                methods_text = ", ".join(detection_methods) if detection_methods else "None"
                logic_op = settings.get("logic_operator", "or").upper()
                logic_symbol = "∧" if logic_op == "AND" else "∨"
                value = (
                    f"**Status:** {status}\n"
                    f"**Detection:** {methods_text}\n"
                    f"**Logic:** {logic_op} {logic_symbol}\n"
                    f"**Time:** {settings.get('time_window', 300)}s\n"
                    f"**Action:** {settings.get('action', 'notify').title()}\n"
                    f"**Channels:** {channel_count} channels"
                )
                embed.add_field(name=f"📋 {rule_name_i}", value=value, inline=True)
        embed.add_field(name="💡 Usage", value="To see details of a specific rule: `!botdetectionsettings <rule_name>`", inline=False)
        await ctx.send(embed=embed)


@bot.command(name="botdetections")
async def botdetections(ctx):
    """Show all bot detection rules (alias for botdetectionsettings)"""
    await botdetectionsettings(ctx)


@bot.command(name="deletebotdetections")
async def deletebotdetections(ctx, rule_name: str):
    """Delete a bot detection rule"""
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return

    guild_id = ctx.guild.id
    rule_name = rule_name.strip().lower()
    if guild_id not in bot_detection_rules:
        await ctx.send("Bu sunucuda bot algılama kuralları tanımlanmamış.")
        return
    guild_rules = bot_detection_rules[guild_id]
    if rule_name not in guild_rules:
        await ctx.send(f"'{rule_name}' adında bir kural bulunamadı.")
        return
    del guild_rules[rule_name]
    if not guild_rules:
        del bot_detection_rules[guild_id]
    await ctx.send(f"✅ **{rule_name}** bot algılama kuralı silindi.")


@bot.command(name="setverifypaneltext")
async def setverifypaneltext(ctx, text_type: str, *, content: str):
    # Security: Only log in debug mode to prevent information disclosure
    if DEBUG_MODE:
        print(f"[DEBUG] setverifypaneltext command triggered by {ctx.author} with type: {text_type}")
    
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        if DEBUG_MODE:
            print(f"[DEBUG] User {ctx.author} not authorized")
        return
    
    if DEBUG_MODE:
        print(f"[DEBUG] User authorized, processing...")
    
    guild_id = ctx.guild.id
    text_type = text_type.lower().strip()
    
    if DEBUG_MODE:
        print(f"[DEBUG] Text type: {text_type}, Content length: {len(content)}")
    
    if text_type not in ["title", "description", "image"]:
        await ctx.send("Please specify either `title`, `description`, or `image`. Examples:\n• `!setverifypaneltext title Welcome to Our Server`\n• `!setverifypaneltext image https://example.com/image.png`")
        if DEBUG_MODE:
            print(f"[DEBUG] Invalid text type: {text_type}")
        return
    
    if text_type == "image":
        if DEBUG_MODE:
            print(f"[DEBUG] Processing image URL: {content[:100]}...")
        
        # Validate URL format (expanded check for various platforms)
        content_lower = content.lower()
        
        # Check for valid URL protocols
        valid_protocols = [
            "http://", "https://", "blob:", "data:"
        ]
        
        if DEBUG_MODE:
            print(f"[DEBUG] Checking protocols...")
        if not any(content.startswith(protocol) for protocol in valid_protocols):
            await ctx.send("Image must be a valid URL starting with http://, https://, blob:, or data:")
            if DEBUG_MODE:
                print(f"[DEBUG] Invalid protocol in URL: {content[:50]}")
            return
        
        if DEBUG_MODE:
            print(f"[DEBUG] Protocol check passed")
        
        # Special handling for different URL types
        if DEBUG_MODE:
            print(f"[DEBUG] Starting platform validation...")
        is_discord_cdn = ("cdn.discordapp.com" in content_lower or 
                         "media.discordapp.net" in content_lower or
                         "images-ext-1.discordapp.net" in content_lower or
                         "images-ext-2.discordapp.net" in content_lower or
                         "discordapp.com/attachments" in content_lower or
                         "discord.com/attachments" in content_lower)
        print(f"[DEBUG] Discord CDN check: {is_discord_cdn}")
        is_whatsapp = "web.whatsapp.com" in content_lower or "whatsapp" in content_lower
        is_blob_url = content.startswith("blob:")
        is_data_url = content.startswith("data:image/")
        is_gif_platform = any(platform in content_lower for platform in [
            "giphy.com", "tenor.com", "gfycat.com", "reddit.com", "redgifs.com"
        ])
        is_video_platform = any(platform in content_lower for platform in [
            "youtube.com", "youtu.be", "vimeo.com", "streamable.com", "twitch.tv", "tiktok.com"
        ])
        is_special_platform = any(platform in content_lower for platform in [
            "imgur.com", "gyazo.com", "prntscr.com", "lightshot.com", 
            "github.com", "githubusercontent.com", "telegram.org", "steamcommunity.com"
        ])
        
        # Check file extensions for regular URLs (images and videos)
        valid_extensions = [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".mp4", ".mov", ".avi", ".webm", ".mkv"]
        has_valid_extension = any(content_lower.endswith(ext) for ext in valid_extensions)
        
        # Security: Only show debug info in debug mode
        if DEBUG_MODE:
            print(f"[DEBUG] All platform checks completed")
            print(f"[DEBUG] Final validation results:")
            print(f"[DEBUG] - Discord CDN: {is_discord_cdn}")
            print(f"[DEBUG] - WhatsApp: {is_whatsapp}")
            print(f"[DEBUG] - Blob URL: {is_blob_url}")
            print(f"[DEBUG] - Data URL: {is_data_url}")
            print(f"[DEBUG] - GIF Platform: {is_gif_platform}")
            print(f"[DEBUG] - Video Platform: {is_video_platform}")
            print(f"[DEBUG] - Special Platform: {is_special_platform}")
            print(f"[DEBUG] - Valid Extension: {has_valid_extension}")
        
        # Allow URL if it meets any of these criteria
        validation_passed = (is_discord_cdn or is_whatsapp or is_blob_url or is_data_url or 
                            is_gif_platform or is_video_platform or is_special_platform or has_valid_extension)
        
        if DEBUG_MODE:
            print(f"[DEBUG] Overall validation result: {validation_passed}")
        
        if not validation_passed:
            # Security: Only show detailed debug info in debug mode
            if DEBUG_MODE:
                debug_info = f"🔍 **URL Validation Debug:**\n"
                debug_info += f"URL: `{content[:100]}{'...' if len(content) > 100 else ''}`\n"
                debug_info += f"Discord CDN: {'✅' if is_discord_cdn else '❌'}\n"
                debug_info += f"WhatsApp: {'✅' if is_whatsapp else '❌'}\n"
                debug_info += f"Blob URL: {'✅' if is_blob_url else '❌'}\n"
                debug_info += f"Data URL: {'✅' if is_data_url else '❌'}\n"
                debug_info += f"GIF Platform: {'✅' if is_gif_platform else '❌'}\n"
                debug_info += f"Video Platform: {'✅' if is_video_platform else '❌'}\n"
                debug_info += f"Special Platform: {'✅' if is_special_platform else '❌'}\n"
                debug_info += f"Valid Extension: {'✅' if has_valid_extension else '❌'}\n"
                
                embed = discord.Embed(
                    title="❌ Image URL Validation Failed",
                    description=debug_info,
                    color=discord.Color.red()
                )
            else:
                embed = discord.Embed(
                    title="❌ Image URL Validation Failed",
                    description="The provided URL is not from a supported platform or doesn't have a valid extension.",
                    color=discord.Color.red()
                )
            
            embed.add_field(
                name="Supported URL Types",
                value=(
                    "• End with a valid image/video extension (.png, .jpg, .jpeg, .gif, .webp, .bmp, .svg, .mp4, .mov, .avi, .webm, .mkv)\n"
                    "• Be a Discord CDN link (cdn.discordapp.com, discord.com/attachments)\n"
                    "• Be a WhatsApp Web link\n"
                    "• Be a blob: or data: URL\n"
                    "• Be from a GIF platform (Giphy, Tenor, Gfycat, Reddit)\n"
                    "• Be from a video platform (YouTube, Vimeo, Streamable, TikTok)\n"
                    "• Be from a supported platform (Imgur, GitHub, Steam, etc.)"
                ),
                inline=False
            )
            await ctx.send(embed=embed)
            return
        else:
            # Success - only show debug info in debug mode
            if DEBUG_MODE:
                print(f"[DEBUG] Validation passed! Sending success message...")
                debug_info = f"🔍 **URL Validation Debug:**\n"
                debug_info += f"URL: `{content[:100]}{'...' if len(content) > 100 else ''}`\n"
                debug_info += f"Discord CDN: {'✅' if is_discord_cdn else '❌'}\n"
                debug_info += f"WhatsApp: {'✅' if is_whatsapp else '❌'}\n"
                debug_info += f"Blob URL: {'✅' if is_blob_url else '❌'}\n"
                debug_info += f"Data URL: {'✅' if is_data_url else '❌'}\n"
                debug_info += f"GIF Platform: {'✅' if is_gif_platform else '❌'}\n"
                debug_info += f"Video Platform: {'✅' if is_video_platform else '❌'}\n"
                debug_info += f"Special Platform: {'✅' if is_special_platform else '❌'}\n"
                debug_info += f"Valid Extension: {'✅' if has_valid_extension else '❌'}\n"
                
                success_embed = discord.Embed(
                    title="✅ Image URL Validation Passed",
                    description=debug_info,
                    color=discord.Color.green()
                )
                await ctx.send(embed=success_embed)
                print(f"[DEBUG] Success message sent")
    
    if len(content) > 256 and text_type == "title":
        await ctx.send("Title must be 256 characters or less.")
        return
    
    if len(content) > 2048 and text_type == "description":
        await ctx.send("Description must be 2048 characters or less.")
        return
    
    if guild_id not in captcha_panel_texts:
        captcha_panel_texts[guild_id] = {
            "title": DEFAULT_PANEL_TITLE,
            "description": DEFAULT_PANEL_DESCRIPTION,
            "image": None
        }
    
    captcha_panel_texts[guild_id][text_type] = content
    
    # Auto-save settings
    auto_save_security_settings()
    
    if text_type == "image":
        await ctx.send(f"Verification panel image updated successfully!\nImage URL: {content}")
    else:
        await ctx.send(f"Verification panel {text_type} updated successfully!")


@bot.command(name="showverifypaneltext")
async def showverifypaneltext(ctx):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    guild_id = ctx.guild.id
    panel_text = captcha_panel_texts.get(guild_id, {
        "title": DEFAULT_PANEL_TITLE,
        "description": DEFAULT_PANEL_DESCRIPTION,
        "image": None
    })
    
    embed = discord.Embed(
        title="Current Verification Panel Text",
        color=discord.Color.blue()
    )
    embed.add_field(name="Title", value=f"```{panel_text['title']}```", inline=False)
    embed.add_field(name="Description", value=f"```{panel_text['description']}```", inline=False)
    
    image_url = panel_text.get('image')
    if image_url:
        embed.add_field(name="Image URL", value=f"```{image_url}```", inline=False)
    else:
        embed.add_field(name="Image URL", value="```Not set```", inline=False)
    
    embed.add_field(
        name="Usage", 
        value="• `!setverifypaneltext title <new title>`\n• `!setverifypaneltext description <new description>`\n• `!setverifypaneltext image <image_url>`", 
        inline=False
    )
    
    await ctx.send(embed=embed)


@bot.command(name="resetverifypaneltext")
async def resetverifypaneltext(ctx):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    guild_id = ctx.guild.id
    if guild_id in captcha_panel_texts:
        del captcha_panel_texts[guild_id]
    
    # Auto-save settings
    auto_save_security_settings()
    
    await ctx.send("Verification panel text reset to default values.")


@bot.command(name="sendverifypanel")
async def sendverifypanel(ctx, channel: str = None):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    # Security: Rate limiting
    if await _handle_security_rate_limit(ctx, "sendverifypanel"):
        return

    target_channel = ctx.channel
    if channel:
        raw = channel.strip()
        if raw.startswith("<#") and raw.endswith(">"):
            raw = raw[2:-1]
        try:
            cid = int(raw)
            ch = ctx.guild.get_channel(cid)
            if ch is not None:
                target_channel = ch
        except ValueError:
            pass

    # Get custom panel text for this guild or use defaults
    guild_id = ctx.guild.id
    panel_text = captcha_panel_texts.get(guild_id, {
        "title": DEFAULT_PANEL_TITLE,
        "description": DEFAULT_PANEL_DESCRIPTION,
        "image": None
    })

    embed = discord.Embed(
        title=panel_text["title"],
        description=panel_text["description"],
        color=discord.Color.green(),
    )
    
    # Add image if set
    image_url = panel_text.get("image")
    if image_url:
        embed.set_image(url=image_url)
    try:
        await target_channel.send(embed=embed, view=CaptchaVerifyView())
        await ctx.send(f"Verification panel sent to: {target_channel.mention}")
    except Exception as e:
        await ctx.send("Failed to send verification panel.")


def _render_captcha_image(code: str) -> bytes:
    # Basic CAPTCHA rendering with noise and slight variations
    width, height = 260, 90
    # Background color (light)
    bg = (random.randint(220, 245), random.randint(220, 245), random.randint(220, 245))
    image = Image.new("RGB", (width, height), bg)
    draw = ImageDraw.Draw(image)

    # Try to load a TTF font; fallback to default
    font = None
    possible_fonts = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for fp in possible_fonts:
        try:
            font = ImageFont.truetype(fp, 42)
            break
        except Exception:
            font = None
    if font is None:
        font = ImageFont.load_default()

    # Draw random lines for noise
    for _ in range(6):
        start = (random.randint(0, width // 2), random.randint(0, height))
        end = (random.randint(width // 2, width), random.randint(0, height))
        color = (random.randint(100, 180), random.randint(100, 180), random.randint(100, 180))
        draw.line([start, end], fill=color, width=random.randint(1, 3))

    # Draw characters with jitter
    char_spacing = width // (len(code) + 2)
    base_x = char_spacing
    for index, ch in enumerate(code):
        # Individual color for each char
        color = (
            random.randint(10, 90),
            random.randint(10, 90),
            random.randint(10, 90),
        )
        # Create a separate layer to rotate character
        char_img = Image.new("RGBA", (60, 60), (0, 0, 0, 0))
        char_draw = ImageDraw.Draw(char_img)
        # Slight size variation
        font_size = random.randint(36, 46)
        try:
            if isinstance(font, ImageFont.FreeTypeFont):
                use_font = ImageFont.truetype(font.path, font_size)
            else:
                use_font = font
        except Exception:
            use_font = font
        # Center roughly
        w, h = char_draw.textsize(ch, font=use_font)
        char_draw.text(((60 - w) / 2, (60 - h) / 2), ch, font=use_font, fill=color)
        angle = random.uniform(-22, 22)
        char_img = char_img.rotate(angle, resample=Image.BICUBIC, expand=1)
        # Paste onto main image
        offset_x = base_x + index * char_spacing + random.randint(-4, 4)
        offset_y = (height - char_img.size[1]) // 2 + random.randint(-6, 6)
        image.paste(char_img, (offset_x, offset_y), char_img)

    # Add random dots
    for _ in range(200):
        x = random.randint(0, width - 1)
        y = random.randint(0, height - 1)
        image.putpixel((x, y), (
            random.randint(180, 230),
            random.randint(180, 230),
            random.randint(180, 230),
        ))

    # Slight blur for anti-OCR
    try:
        image = image.filter(ImageFilter.GaussianBlur(radius=0.6))
    except Exception:
        pass

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()

# Get bot token from environment variable
bot_token = os.getenv("PLAYBOT")
if not bot_token:
    print("❌ CRITICAL ERROR: PLAYBOT environment variable not found!")
    print("Please set your bot token as an environment variable:")
    print("export PLAYBOT='your_bot_token_here'")
    print("or create a .env file with: PLAYBOT=your_bot_token_here")
    exit(1)

print("✅ Bot token loaded from environment variable")
try:
    import atexit
    atexit.register(_save_bot_data)
    print("[persistence] Registered shutdown data save")
except Exception as e:
    print(f"[persistence] Could not register shutdown save: {e}")

try:
    bot.run(bot_token)
except KeyboardInterrupt:
    print("[persistence] Bot shutdown requested, saving data...")
    _save_bot_data()
    print("[persistence] Data saved on shutdown")
except Exception as e:
    print(f"[bot] Error running bot: {e}")
    _save_bot_data()
    print("[persistence] Data saved after error")
