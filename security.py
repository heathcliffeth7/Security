import discord
from discord.ext import commands
import os
from datetime import datetime, timedelta
import dotenv   # For .env file support
import re
import random
import string
import io
import asyncio
from collections import defaultdict
import shlex
from difflib import SequenceMatcher
import time
import signal
import threading
import json
import copy
from pathlib import Path
from typing import List, Optional, Set
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
def _parse_role_ids(env_value: str | None) -> Set[int]:
    ids: Set[int] = set()
    if not env_value:
        return ids
    for token in env_value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            ids.add(int(token))
        except ValueError:
            print(f"⚠️  WARNING: Invalid SECURITY_MANAGER_ROLE_ID entry ignored: {token!r}")
    return ids


security_authorized_role_ids: Set[int] = _parse_role_ids(os.getenv("SECURITY_MANAGER_ROLE_ID"))
if not security_authorized_role_ids:
    print("⚠️  WARNING: SECURITY_MANAGER_ROLE_ID environment variable not set or invalid!")
    print("Security commands will only work with manually added IDs via !securityauthorizedadd")
    print("To set default security roles: export SECURITY_MANAGER_ROLE_ID='id1,id2,...'")

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

# Security settings file path
SECURITY_SETTINGS_FILE = "security_settings.json"

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

# Spam violation statistics configuration
SPAM_STATS_FILE = Path(__file__).with_name("spam_violation_stats.json")
SPAM_AGGREGATE_WINDOWS = [
    ("24h", 1),
    ("7d", 7),
    ("30d", 30),
    ("90d", 90),
    ("120d", 120),
    ("180d", 180),
    ("360d", 360),
]
MAX_SPAM_AGGREGATE_DAYS = 360
spam_violation_stats = {}
spam_stats_loaded = False
spam_stats_lock = asyncio.Lock()

# ============== SECURITY SETTINGS PERSISTENCE ==============

def save_security_settings():
    """Save all security settings to JSON file"""
    try:
        # Convert regex settings to serializable format
        serializable_regex_settings = {}
        for guild_id, guild_rules in regex_settings_by_guild.items():
            serializable_regex_settings[str(guild_id)] = {}
            for rule_name, rule_data in guild_rules.items():
                serializable_regex_settings[str(guild_id)][rule_name] = {
                    "pattern": rule_data.get("pattern", ""),
                    "channels": list(rule_data.get("channels", set())),
                    "exempt_users": list(rule_data.get("exempt_users", set())),
                    "exempt_roles": list(rule_data.get("exempt_roles", set()))
                }
        
        # Serialize spam rules
        serializable_spam_rules = {}
        for guild_id, guild_rules in spam_rules_by_guild.items():
            serializable_spam_rules[str(guild_id)] = {}
            for rule_name, rule_data in guild_rules.items():
                serializable_spam_rules[str(guild_id)][rule_name] = {
                    "label": rule_data.get("label", rule_name),
                    "min_length": rule_data.get("min_length", 0),
                    "similarity_threshold": rule_data.get("similarity_threshold", 0.0),
                    "time_window": rule_data.get("time_window", 0),
                    "message_count": rule_data.get("message_count", 0),
                    "dm_message": rule_data.get("dm_message", ""),
                    "notify_channel_id": rule_data.get("notify_channel_id"),
                    "channels": list(rule_data.get("channels", set())),
                    "nonreply_only": rule_data.get("nonreply_only", False)
                }
        
        # Serialize captcha panel texts
        serializable_panel_texts = {}
        for guild_id, panel_data in captcha_panel_texts.items():
            serializable_panel_texts[str(guild_id)] = panel_data
        
        settings_data = {
            "version": "1.0",
            "timestamp": time.time(),
            
            # Global Security Filters
            "no_avatar_filter_enabled": no_avatar_filter_enabled,
            "no_avatar_action": no_avatar_action,
            "no_avatar_timeout_duration": no_avatar_timeout_duration,
            
            "account_age_filter_enabled": account_age_filter_enabled,
            "account_age_min_days": account_age_min_days,
            "account_age_action": account_age_action,
            "account_age_timeout_duration": account_age_timeout_duration,
            
            # Security Authorization
            "security_authorized_ids": list(security_authorized_ids),
            
            # CAPTCHA Settings
            "captcha_verify_role_id": captcha_verify_role_id,
            "captcha_panel_texts": serializable_panel_texts,
            
            # Regex Settings
            "regex_settings_by_guild": serializable_regex_settings,
            
            # Spam Settings
            "spam_rules_by_guild": serializable_spam_rules,
            
            # Verify button usage (for statistics only)
            "verify_button_usage": dict(verify_button_usage)
        }
        
        # Backup existing file if present
        if os.path.exists(SECURITY_SETTINGS_FILE):
            backup_file = f"{SECURITY_SETTINGS_FILE}.backup"
            try:
                os.rename(SECURITY_SETTINGS_FILE, backup_file)
                print(f"[SECURITY] Backup created: {backup_file}")
            except Exception as e:
                print(f"[SECURITY] Warning: Could not create backup: {e}")
        
        # Save new settings
        with open(SECURITY_SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings_data, f, indent=2, ensure_ascii=False)
        
        print(f"[SECURITY] Settings saved successfully to {SECURITY_SETTINGS_FILE}")
        return True
        
    except Exception as e:
        print(f"[SECURITY] Error saving settings: {e}")
        return False

def load_security_settings():
    """Load security settings from JSON file"""
    global no_avatar_filter_enabled, no_avatar_action, no_avatar_timeout_duration
    global account_age_filter_enabled, account_age_min_days, account_age_action, account_age_timeout_duration
    global security_authorized_ids, captcha_verify_role_id, captcha_panel_texts
    global regex_settings_by_guild, verify_button_usage, spam_rules_by_guild
    
    try:
        if not os.path.exists(SECURITY_SETTINGS_FILE):
            print(f"[SECURITY] No settings file found at {SECURITY_SETTINGS_FILE}, using defaults")
            return False
        
        with open(SECURITY_SETTINGS_FILE, 'r', encoding='utf-8') as f:
            settings_data = json.load(f)
        
        # Version control
        version = settings_data.get("version", "unknown")
        print(f"[SECURITY] Loading settings version: {version}")
        
        # Global Security Filters
        no_avatar_filter_enabled = settings_data.get("no_avatar_filter_enabled", False)
        no_avatar_action = settings_data.get("no_avatar_action", None)
        no_avatar_timeout_duration = settings_data.get("no_avatar_timeout_duration", None)
        
        account_age_filter_enabled = settings_data.get("account_age_filter_enabled", False)
        account_age_min_days = settings_data.get("account_age_min_days", None)
        account_age_action = settings_data.get("account_age_action", None)
        account_age_timeout_duration = settings_data.get("account_age_timeout_duration", None)
        
        # Security Authorization
        security_authorized_ids = set(settings_data.get("security_authorized_ids", []))
        
        # CAPTCHA Settings
        captcha_verify_role_id = settings_data.get("captcha_verify_role_id", None)
        
        # Panel texts
        panel_texts_data = settings_data.get("captcha_panel_texts", {})
        captcha_panel_texts.clear()
        for guild_id_str, panel_data in panel_texts_data.items():
            try:
                guild_id = int(guild_id_str)
                captcha_panel_texts[guild_id] = panel_data
            except ValueError:
                print(f"[SECURITY] Warning: Invalid guild ID in panel texts: {guild_id_str}")
        
        # Regex Settings
        regex_data = settings_data.get("regex_settings_by_guild", {})
        regex_settings_by_guild.clear()
        for guild_id_str, guild_rules in regex_data.items():
            try:
                guild_id = int(guild_id_str)
                regex_settings_by_guild[guild_id] = {}
                
                for rule_name, rule_data in guild_rules.items():
                    pattern = rule_data.get("pattern", "")
                    if pattern:
                        try:
                            # Pattern'i yeniden compile et
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
                            print(f"[SECURITY] Warning: Could not compile regex pattern '{pattern}': {e}")
            except ValueError:
                print(f"[SECURITY] Warning: Invalid guild ID in regex settings: {guild_id_str}")
        
        # Spam Settings
        spam_data = settings_data.get("spam_rules_by_guild", {})
        spam_rules_by_guild.clear()
        for guild_id_str, guild_rules in spam_data.items():
            try:
                guild_id = int(guild_id_str)
            except ValueError:
                print(f"[SECURITY] Warning: Invalid guild ID in spam settings: {guild_id_str}")
                continue
            spam_rules_by_guild[guild_id] = {}
            for rule_name, rule_data in guild_rules.items():
                try:
                    label = str(rule_data.get("label", rule_name))
                    min_length = int(rule_data.get("min_length", 0))
                    similarity_threshold = float(rule_data.get("similarity_threshold", 0.0))
                    time_window = int(rule_data.get("time_window", 0))
                    message_count = int(rule_data.get("message_count", 0))
                    dm_message = str(rule_data.get("dm_message", ""))
                    notify_channel_id = rule_data.get("notify_channel_id")
                    if notify_channel_id is not None:
                        notify_channel_id = int(notify_channel_id)
                    spam_rules_by_guild[guild_id][rule_name] = {
                        "label": label,
                        "min_length": max(0, min_length),
                        "similarity_threshold": max(0.0, min(similarity_threshold, 1.0)),
                        "time_window": max(0, time_window),
                        "message_count": max(0, message_count),
                        "dm_message": dm_message,
                        "notify_channel_id": notify_channel_id,
                        "channels": set(rule_data.get("channels", [])),
                        "nonreply_only": _coerce_bool(rule_data.get("nonreply_only", False))
                    }
                except Exception as e:
                    print(f"[SECURITY] Warning: Could not load spam rule '{rule_name}' for guild {guild_id_str}: {e}")
        
        # Verify button usage
        usage_data = settings_data.get("verify_button_usage", {})
        verify_button_usage.clear()
        for user_id_str, count in usage_data.items():
            try:
                user_id = int(user_id_str)
                verify_button_usage[user_id] = count
            except ValueError:
                print(f"[SECURITY] Warning: Invalid user ID in verify button usage: {user_id_str}")
        
        # Loading statistics
        timestamp = settings_data.get("timestamp", 0)
        if timestamp:
            import datetime
            load_time = datetime.datetime.fromtimestamp(timestamp)
            print(f"[SECURITY] Settings loaded successfully (saved: {load_time.strftime('%Y-%m-%d %H:%M:%S')})")
        else:
            print(f"[SECURITY] Settings loaded successfully")
        
        # Summary of loaded settings
        print(f"[SECURITY] Loaded settings summary:")
        print(f"  - No-avatar filter: {'ON' if no_avatar_filter_enabled else 'OFF'}")
        print(f"  - Account age filter: {'ON' if account_age_filter_enabled else 'OFF'}")
        print(f"  - Authorized IDs: {len(security_authorized_ids)}")
        print(f"  - Captcha role ID: {captcha_verify_role_id}")
        print(f"  - Panel texts for {len(captcha_panel_texts)} guilds")
        print(f"  - Regex rules for {len(regex_settings_by_guild)} guilds")
        if spam_rules_by_guild:
            total_spam_rules = sum(len(rules) for rules in spam_rules_by_guild.values())
            print(f"  - Spam rules: {total_spam_rules} rules in {len(spam_rules_by_guild)} guilds")
        print(f"  - Verify button usage for {len(verify_button_usage)} users")

        return True

    except Exception as e:
        print(f"[SECURITY] Error loading settings: {e}")
        return False


def load_spam_violation_stats():
    """Load persisted spam violation statistics from disk."""
    global spam_violation_stats, spam_stats_loaded
    try:
        if SPAM_STATS_FILE.exists():
            with open(SPAM_STATS_FILE, "r", encoding="utf-8") as handle:
                spam_violation_stats = json.load(handle)
        else:
            spam_violation_stats = {}
    except Exception as exc:
        print(f"[SECURITY] Error loading spam stats: {exc}")
        spam_violation_stats = {}
    finally:
        spam_stats_loaded = True


def _parse_date_key(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except Exception:
        return None


def _prune_spam_daily_counts(daily_counts):
    """Keep only the most recent configured number of days in daily counts."""
    if not daily_counts:
        return
    today = datetime.utcnow().date()
    cutoff = today - timedelta(days=MAX_SPAM_AGGREGATE_DAYS - 1)
    stale_keys = []
    for key in list(daily_counts.keys()):
        date_obj = _parse_date_key(key)
        if date_obj is None or date_obj < cutoff:
            stale_keys.append(key)
    for key in stale_keys:
        daily_counts.pop(key, None)


def _calculate_spam_aggregates(daily_counts):
    """Calculate window aggregates from per-day counts."""
    aggregates = {}
    today = datetime.utcnow().date()
    for label, days in SPAM_AGGREGATE_WINDOWS:
        cutoff = today - timedelta(days=days - 1)
        total = 0
        for key, value in daily_counts.items():
            date_obj = _parse_date_key(key)
            if date_obj is None:
                continue
            if date_obj >= cutoff:
                try:
                    total += int(value)
                except (TypeError, ValueError):
                    continue
        aggregates[label] = total
    return aggregates


async def _save_spam_violation_stats():
    """Persist spam violation statistics to disk."""
    async with spam_stats_lock:
        snapshot = copy.deepcopy(spam_violation_stats)

    def _write_snapshot():
        try:
            temp_path = SPAM_STATS_FILE.with_suffix(".tmp")
            with open(temp_path, "w", encoding="utf-8") as handle:
                json.dump(snapshot, handle, indent=2, ensure_ascii=False)
            temp_path.replace(SPAM_STATS_FILE)
        except Exception as exc:
            print(f"[SECURITY] Error saving spam stats: {exc}")

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _write_snapshot)


async def record_spam_violation(guild_id, user_id, rule_key, label=""):
    """Record a spam violation and update rolling aggregates."""
    global spam_stats_loaded
    if not spam_stats_loaded:
        load_spam_violation_stats()

    today_key = datetime.utcnow().strftime("%Y-%m-%d")

    async with spam_stats_lock:
        guild_key = str(guild_id)
        user_key = str(user_id)
        guild_bucket = spam_violation_stats.setdefault(guild_key, {})
        user_bucket = guild_bucket.setdefault(user_key, {})
        rule_bucket = user_bucket.setdefault(rule_key, {
            "label": label or rule_key,
            "daily_counts": {},
            "aggregates": {},
        })

        rule_bucket["label"] = label or rule_bucket.get("label") or rule_key

        daily_counts = rule_bucket.setdefault("daily_counts", {})
        daily_counts[today_key] = int(daily_counts.get(today_key, 0)) + 1

        _prune_spam_daily_counts(daily_counts)
        rule_bucket["aggregates"] = _calculate_spam_aggregates(daily_counts)
        rule_bucket["last_updated"] = today_key

    await _save_spam_violation_stats()


async def remove_spam_violation_stats_for_rule(guild_id, rule_key):
    """Remove stored violation statistics for a specific rule."""
    global spam_stats_loaded
    if not spam_stats_loaded:
        load_spam_violation_stats()

    guild_key = str(guild_id)
    async with spam_stats_lock:
        guild_bucket = spam_violation_stats.get(guild_key)
        if not guild_bucket:
            return

        empty_users = []
        for user_key, user_bucket in guild_bucket.items():
            if rule_key in user_bucket:
                user_bucket.pop(rule_key, None)
            if not user_bucket:
                empty_users.append(user_key)

        for user_key in empty_users:
            guild_bucket.pop(user_key, None)

        if not guild_bucket:
            spam_violation_stats.pop(guild_key, None)

    await _save_spam_violation_stats()

def is_security_authorized(ctx):
    if security_authorized_role_ids and any(role.id in security_authorized_role_ids for role in ctx.author.roles):
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

# Spam moderation settings per guild
# Structure: { guild_id: { name: {"min_length": int, "similarity_threshold": float, "time_window": int, "message_count": int, "dm_message": str, "notify_channel_id": int, "channels": set[int], "nonreply_only": bool} } }
spam_rules_by_guild = {}


def _coerce_bool(value) -> bool:
    """Coerce various truthy representations into a real boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on", "enable", "enabled"}:
            return True
        if lowered in {"0", "false", "no", "off", "disable", "disabled"}:
            return False
        return bool(lowered)
    if isinstance(value, (int, float)):
        return value != 0
    return bool(value)

# Commonly used time windows supported out-of-the-box (value in seconds)
SPAM_RULE_PREDEFINED_WINDOWS = {
    "24h": 24 * 3600,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "60d": 60 * 86400,
    "90d": 90 * 86400,
    "120d": 120 * 86400,
    "180d": 180 * 86400,
    "360d": 360 * 86400,
}

# Runtime spam tracking (not persisted)
# Key: (guild_id, user_id) -> list[{"timestamp": float, "content": str}]
spam_message_history = defaultdict(list)

# Last trigger timestamps to prevent duplicate alerts within the window
# Key: (guild_id, user_id, rule_name) -> float
spam_rule_trigger_log = {}


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

def _collect_regex_text_blocks(
    message: discord.Message,
    *,
    _seen: Optional[Set[int]] = None
) -> List[str]:
    """Return textual fragments that should be scanned by regex rules."""
    blocks: List[str] = []
    seen: Set[int] = _seen or set()

    message_id = getattr(message, "id", None)
    if message_id is not None:
        if message_id in seen:
            return blocks
        seen.add(message_id)

    content = getattr(message, "content", None)
    if content:
        blocks.append(content)

    for embed in getattr(message, "embeds", []) or []:
        title = getattr(embed, "title", None)
        if title:
            blocks.append(title)
        description = getattr(embed, "description", None)
        if description:
            blocks.append(description)
        for field in getattr(embed, "fields", []) or []:
            field_name = getattr(field, "name", None)
            field_value = getattr(field, "value", None)
            if field_name:
                blocks.append(field_name)
            if field_value:
                blocks.append(field_value)
        footer = getattr(embed, "footer", None)
        if footer and getattr(footer, "text", None):
            blocks.append(footer.text)
        author = getattr(embed, "author", None)
        if author and getattr(author, "name", None):
            blocks.append(author.name)

    reference = getattr(message, "reference", None)
    if reference:
        resolved = getattr(reference, "resolved", None)
        cached = getattr(reference, "cached_message", None)
        target = None
        if isinstance(resolved, discord.Message):
            target = resolved
        elif isinstance(cached, discord.Message):
            target = cached
        if target is not None:
            blocks.extend(_collect_regex_text_blocks(target, _seen=seen))

    return [block for block in blocks if isinstance(block, str) and block.strip()]


# Helper function for regex moderation (shared by on_message and on_message_edit)
async def _check_message_against_regex(message: discord.Message):
    """Check message against regex rules and delete if it matches"""
    if message.author.bot:
        return
    if message.guild is None:
        return

    text_blocks = _collect_regex_text_blocks(message)
    if not text_blocks:
        return

    guild_rules = regex_settings_by_guild.get(message.guild.id)
    if not guild_rules:
        return

    channel_id = message.channel.id
    for rule in guild_rules.values():
        channels = rule.get("channels", set())
        compiled = rule.get("compiled")
        if not compiled or not channels:
            continue
        if channel_id not in channels:
            continue

        if not any(_safe_regex_search(compiled, text) for text in text_blocks):
            continue

        exempt_users = rule.get("exempt_users", set())
        if message.author.id in exempt_users:
            continue
        exempt_roles = rule.get("exempt_roles", set())
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

def _is_message_reply(message: discord.Message) -> bool:
    """
    Return True if message is a Discord reply (covers uncached targets).

    This function checks multiple indicators to determine if a message is a reply:
    1. Checks if message has a reference object
    2. Checks if reference contains resolved message data
    3. Checks if reference contains message/channel/guild IDs
    4. Checks if message type is explicitly marked as reply

    Args:
        message: Discord Message object to check

    Returns:
        bool: True if message is a reply, False otherwise
    """
    ref = getattr(message, "reference", None)
    if ref is not None:
        # Discord replies always include a reference payload; treat any reference as a reply
        if getattr(ref, "resolved", None) is not None:
            return True
        if any(getattr(ref, attr, None) for attr in ("message_id", "channel_id", "guild_id")):
            return True
        return True
    try:
        if message.type == discord.MessageType.reply:
            return True
    except AttributeError:
        pass
    return False


async def _check_message_against_spam_rules(message: discord.Message):
    """Check message against custom spam rules and apply configured actions"""
    if message.author.bot:
        return
    if message.guild is None:
        return

    # Skip security managers / authorized users
    author_roles = getattr(message.author, "roles", []) or []
    if security_authorized_role_ids and any(r.id in security_authorized_role_ids for r in author_roles):
        return
    if message.author.id in security_authorized_ids:
        return
    if any(r.id in security_authorized_ids for r in author_roles):
        return

    guild_rules = spam_rules_by_guild.get(message.guild.id)
    if not guild_rules:
        return

    content = message.content or ""
    if not content:
        return

    now = time.time()
    history_key = (message.guild.id, message.author.id)
    user_history = spam_message_history[history_key]

    is_reply = _is_message_reply(message)

    max_window = 0
    for rule in guild_rules.values():
        window = rule.get("time_window", 0)
        if window > max_window:
            max_window = window

    if max_window > 0:
        user_history[:] = [entry for entry in user_history if now - entry["timestamp"] <= max_window]
    else:
        user_history.clear()

    user_history.append({
        "timestamp": now,
        "content": content,
        "is_reply": is_reply,
        "channel_id": message.channel.id,
    })

    for name_key, rule in guild_rules.items():
        channels = rule.get("channels", set())
        if channels and message.channel.id not in channels:
            continue

        nonreply_only = rule.get("nonreply_only", False)
        # Skip this rule for reply messages if nonreply_only is enabled
        if nonreply_only and is_reply:
            continue

        min_length = rule.get("min_length", 0)
        if min_length and len(content) <= min_length:
            continue

        time_window = rule.get("time_window", 0)
        if time_window <= 0:
            continue

        message_count = rule.get("message_count", 0)
        if message_count <= 1:
            continue

        similarity_threshold = rule.get("similarity_threshold", 0.0)
        if similarity_threshold <= 0:
            continue

        relevant_messages = [
            entry
            for entry in user_history
            if now - entry["timestamp"] <= time_window
            and (
                not channels
                or entry.get("channel_id") is None
                or entry["channel_id"] in channels
            )
        ]
        # Filter out reply messages for nonreply_only rules
        if nonreply_only:
            relevant_messages = [
                entry for entry in relevant_messages
                if not _coerce_bool(entry.get("is_reply", False))
            ]
        if len(relevant_messages) < message_count:
            continue

        similar_count = 0
        for entry in relevant_messages:
            ratio = SequenceMatcher(None, content, entry["content"]).ratio()
            if ratio >= similarity_threshold:
                similar_count += 1
        if similar_count >= message_count:
            await _handle_spam_rule_trigger(message, name_key, rule)
            continue

async def _handle_spam_rule_trigger(message: discord.Message, rule_key: str, rule: dict):
    """Execute actions when a spam rule is triggered"""
    guild_id = message.guild.id
    user_id = message.author.id
    now = time.time()

    cooldown = max(rule.get("time_window", 0), 60)
    last_trigger = spam_rule_trigger_log.get((guild_id, user_id, rule_key))
    if last_trigger and now - last_trigger < cooldown:
        return

    spam_rule_trigger_log[(guild_id, user_id, rule_key)] = now

    await record_spam_violation(guild_id, user_id, rule_key, label=rule.get("label", rule_key))

    dm_message = rule.get("dm_message")
    if dm_message:
        try:
            await message.author.send(dm_message)
        except discord.Forbidden:
            print(f"[SECURITY] Unable to DM user {user_id} for spam rule '{rule_key}'")
        except discord.HTTPException as e:
            print(f"[SECURITY] HTTP error sending DM: {e}")
        except Exception as e:
            print(f"[SECURITY] Unexpected error sending DM: {e}")

    notify_channel_id = rule.get("notify_channel_id")
    if notify_channel_id:
        channel = message.guild.get_channel(notify_channel_id)
        if channel:
            label = rule.get("label", rule_key)
            window_seconds = rule.get("time_window", 0)
            try:
                preview = message.content[:1500].strip()
                if not preview:
                    preview = "(no content)"
                await channel.send(
                    f"⚠️ Spam rule `{label}` triggered by {message.author.mention} in {message.channel.mention}.\n"
                    f"Window: {window_seconds} seconds | Similarity ≥ {int(rule.get('similarity_threshold', 0.0) * 100)}% | Count ≥ {rule.get('message_count', 0)}\n"
                    f"Recent message:\n```{preview}```"
                )
            except discord.HTTPException as e:
                print(f"[SECURITY] HTTP error notifying channel {notify_channel_id}: {e}")
            except Exception as e:
                print(f"[SECURITY] Unexpected error notifying channel {notify_channel_id}: {e}")
        else:
            print(f"[SECURITY] Notification channel {notify_channel_id} not found for spam rule '{rule_key}'")

# Message moderation via regex
@bot.event
async def on_message(message: discord.Message):
    # Let command processor run only in guilds
    if message.guild and isinstance(bot.command_prefix, str) and message.content.startswith(bot.command_prefix):
        await bot.process_commands(message)
        return
    
    # Check message against regex rules
    await _check_message_against_regex(message)

    # Check custom spam rules
    await _check_message_against_spam_rules(message)

# Message edit moderation via regex
@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    """Check edited messages against regex rules"""
    # Only check the edited message (after)
    await _check_message_against_regex(after)

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
    
    # Save settings
    save_security_settings()
    
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
    
    # Save settings
    save_security_settings()
    
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
    display_labels: list[str] = []
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
            display_labels.append(role.name or f"Role {role.id}")
        else:
            member = ctx.guild.get_member(_id)
            if member is None:
                invalid.append(tok)
                continue
            display_labels.append(member.mention)
        selected.add(_id)
    if not selected:
        await ctx.send("Please specify valid targets. Examples:\n- `!setregexexempt spam users @alice @bob`\n- `!setregexexempt spam roles @Admin 123456789012345678`")
        return
    if kind_l == "roles":
        guild_rules[name_key]["exempt_roles"] = selected
        names = ", ".join(display_labels)
        msg = f"Exempt roles updated for `{regexsettingsname}`: {names}"
    else:
        guild_rules[name_key]["exempt_users"] = selected
        mentions = ", ".join(display_labels)
        msg = f"Exempt users updated for `{regexsettingsname}`: {mentions}"
    
    # Save settings
    save_security_settings()
    
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
    
    # Save settings
    save_security_settings()
    
    await ctx.send(f"Regex setting deleted: `{regexsettingsname}`")

@bot.command(name="spamrule")
async def spamrule(ctx, rulename: str, *, rule_spec: str = ""):
    """Create or update a spam rule with similarity detection"""
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return

    if ctx.guild is None:
        await ctx.send("This command can only be used inside a server.")
        return

    if await _handle_security_rate_limit(ctx, "spamrule"):
        return

    rule_spec = (rule_spec or "").strip()
    if not rule_spec:
        await ctx.send(
            "Please provide rule details. Example: `!spamrule test characters>30 %80 24h message>3 dm \"Your DM\" modlogchannel #alerts`."
        )
        return

    try:
        parts = shlex.split(rule_spec)
    except ValueError as exc:
        await ctx.send(f"Unable to parse command parameters: {exc}")
        return

    if len(parts) < 6:
        await ctx.send(
            "Invalid format. Expected `characters>`, `%`, `<duration>`, `message>`, `dm`, then your DM text and channels."
        )
        return

    length_token = parts.pop(0)
    length_match = re.fullmatch(r"characters\s*>\s*(\d+)", length_token, flags=re.IGNORECASE)
    if not length_match:
        await ctx.send("Specify minimum characters like `characters>30`.")
        return
    min_length = int(length_match.group(1))

    similarity_token = parts.pop(0)
    similarity_match = None
    for pattern in (r"%\s*(\d+(?:\.\d+)?)", r"(\d+(?:\.\d+)?)%", r"similarity\s*>\s*(\d+(?:\.\d+)?)"):
        similarity_match = re.fullmatch(pattern, similarity_token, flags=re.IGNORECASE)
        if similarity_match:
            break
    if not similarity_match:
        await ctx.send("Specify similarity like `%80` or `80%`.")
        return
    similarity_value = float(similarity_match.group(1))
    similarity_threshold = max(0.0, min(similarity_value / 100.0, 1.0))

    duration_token = parts.pop(0).lower()
    duration_display = duration_token
    time_window = SPAM_RULE_PREDEFINED_WINDOWS.get(duration_token)
    if time_window is not None:
        duration_match = re.fullmatch(r"(\d+)([a-z]+)", duration_token)
    else:
        duration_match = re.fullmatch(r"(\d+)([smhd])", duration_token)
        if not duration_match:
            await ctx.send("Specify time window like `24h`, `7d`, or `120s`.")
            return
        window_value = int(duration_match.group(1))
        window_unit = duration_match.group(2)
        unit_multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        time_window = window_value * unit_multipliers[window_unit]
        duration_display = f"{window_value}{window_unit}"

    message_token = parts.pop(0)
    message_match = re.fullmatch(r"messages?\s*>\s*(\d+)", message_token, flags=re.IGNORECASE)
    if not message_match:
        await ctx.send("Specify message threshold like `message>3` or `messages>3`.")
        return
    message_count = int(message_match.group(1))

    if not parts:
        await ctx.send("Please include `dm` followed by the message to send.")
        return

    dm_token = parts.pop(0)
    if dm_token.lower() != "dm":
        await ctx.send("Expected `dm` keyword right after the threshold parameters.")
        return

    KEYWORDS = {"modlogchannel", "specchannel", "nonreply"}

    def _is_keyword(token: str) -> bool:
        lowered = token.lower()
        return lowered in KEYWORDS or lowered.startswith("nonreply")

    dm_tokens: list[str] = []
    while parts and not _is_keyword(parts[0]):
        dm_tokens.append(parts.pop(0))

    if not dm_tokens:
        await ctx.send("Provide the message to send via DM after the `dm` keyword (wrap in quotes if it has spaces).")
        return

    dm_message = " ".join(dm_tokens).strip()
    if not dm_message:
        await ctx.send("Provide the message to send via DM after the `dm` keyword (wrap in quotes if it has spaces).")
        return

    def _resolve_channel(token: str) -> discord.abc.GuildChannel | None:
        raw = token.strip()
        if raw.startswith("<#") and raw.endswith(">"):
            try:
                channel_id_inner = int(raw[2:-1])
            except ValueError:
                return None
            return ctx.guild.get_channel(channel_id_inner)
        if raw.startswith("#"):
            name_inner = raw[1:]
            return discord.utils.get(ctx.guild.text_channels, name=name_inner)
        try:
            channel_id_inner = int(raw)
        except ValueError:
            return None
        return ctx.guild.get_channel(channel_id_inner)

    notify_channel: discord.TextChannel | None = None
    monitored_channels: set[int] = set()
    nonreply_only = False

    while parts:
        token = parts.pop(0)
        lowered = token.lower()
        if lowered == "modlogchannel":
            if not parts:
                await ctx.send("Please provide a channel after `modlogchannel`.")
                return
            channel_token = parts.pop(0)
            channel = _resolve_channel(channel_token)
            if not isinstance(channel, discord.TextChannel):
                await ctx.send("Please mention a valid text channel after `modlogchannel`.")
                return
            notify_channel = channel
            continue
        if lowered == "specchannel":
            if not parts:
                await ctx.send("Provide at least one channel after `specchannel`.")
                return
            spec_found = False
            while parts and not _is_keyword(parts[0]):
                channel_token = parts.pop(0)
                channel = _resolve_channel(channel_token)
                if not isinstance(channel, discord.TextChannel):
                    await ctx.send("`specchannel` must be followed by valid text channel mentions.")
                    return
                monitored_channels.add(channel.id)
                spec_found = True
            if not spec_found:
                await ctx.send("Provide at least one channel after `specchannel`.")
                return
            continue
        if lowered.startswith("nonreply"):
            state_token = None

            # Allow inline forms like nonreply=on or nonreply:on
            inline = lowered[len("nonreply"):].lstrip(" =:")
            if inline:
                state_token = inline

            if state_token is None and parts and not _is_keyword(parts[0]):
                state_token = parts.pop(0).lower()

            if state_token is None:
                nonreply_only = True
                continue
            if state_token in ("on", "true", "yes", "1", "enable", "enabled"):
                nonreply_only = True
                continue
            if state_token in ("off", "false", "no", "0", "disable", "disabled"):
                nonreply_only = False
                continue
            await ctx.send("Use `nonreply on` or `nonreply off` (inline forms like `nonreply=on` also work).")
            return

        channel = _resolve_channel(token)
        if isinstance(channel, discord.TextChannel):
            if notify_channel is None:
                notify_channel = channel
            else:
                monitored_channels.add(channel.id)
            continue

        await ctx.send(f"Unrecognized token `{token}` in command arguments.")
        return

    if notify_channel is None:
        await ctx.send(
            "Please specify the moderation alert channel using `modlogchannel #channel` (or mention a channel directly)."
        )
        return

    monitored_channels = {cid for cid in monitored_channels if ctx.guild.get_channel(cid)}

    guild_id = ctx.guild.id
    name_key = rulename.strip().lower()
    label = rulename.strip() or name_key

    guild_rules = spam_rules_by_guild.setdefault(guild_id, {})
    guild_rules[name_key] = {
        "label": label,
        "min_length": max(0, min_length),
        "similarity_threshold": similarity_threshold,
        "time_window": max(0, time_window),
        "message_count": max(0, message_count),
        "dm_message": dm_message,
        "notify_channel_id": notify_channel.id,
        "channels": monitored_channels,
        "nonreply_only": nonreply_only,
    }

    save_security_settings()

    details = [
        f"Spam rule `{label}` saved.",
        f"- Min characters: {min_length}",
        f"- Similarity: {similarity_threshold * 100:.0f}%",
        f"- Window: {duration_display}",
        f"- Message count: {message_count}",
        f"- Notify: {notify_channel.mention}",
    ]
    if monitored_channels:
        channel_mentions = ", ".join(f"<#{cid}>" for cid in monitored_channels)
        details.append(f"- Monitored channels: {channel_mentions}")
    else:
        details.append("- Monitored channels: all text channels")
    details.append(f"- Count only non-replies: {'Yes' if nonreply_only else 'No'}")

    await ctx.send("\n".join(details))

@bot.command(name="removespamrule")
async def removespamrule(ctx, rulename: str):
    """Remove a previously configured spam rule"""
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return

    if ctx.guild is None:
        await ctx.send("This command can only be used inside a server.")
        return

    if await _handle_security_rate_limit(ctx, "removespamrule"):
        return

    guild_id = ctx.guild.id
    guild_rules = spam_rules_by_guild.get(guild_id)
    if not guild_rules:
        await ctx.send("No spam rules are configured for this server.")
        return

    name_key = rulename.strip().lower()
    if name_key not in guild_rules:
        await ctx.send("No spam rule found with that name.")
        return

    removed_rule = guild_rules.pop(name_key, None)
    if not guild_rules:
        try:
            del spam_rules_by_guild[guild_id]
        except KeyError:
            pass

    # Clean trigger log entries for this rule in this guild
    keys_to_delete = [key for key in spam_rule_trigger_log if key[0] == guild_id and key[2] == name_key]
    for key in keys_to_delete:
        del spam_rule_trigger_log[key]

    # Save settings after removal
    save_security_settings()

    await remove_spam_violation_stats_for_rule(guild_id, name_key)

    label = removed_rule.get("label") if removed_rule else rulename
    await ctx.send(f"Spam rule `{label}` has been removed.")


@bot.command(name="spamrules")
async def spamrules(ctx):
    """List configured spam rules"""
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return

    if ctx.guild is None:
        await ctx.send("This command can only be used inside a server.")
        return

    guild_rules = spam_rules_by_guild.get(ctx.guild.id)
    if not guild_rules:
        await ctx.send("No spam rules are currently configured for this server.")
        return

    def _format_window(seconds: int) -> str:
        seconds = max(0, int(seconds))
        if seconds == 0:
            return "0s"
        if seconds % 86400 == 0:
            return f"{seconds // 86400}d"
        if seconds % 3600 == 0:
            return f"{seconds // 3600}h"
        if seconds % 60 == 0:
            return f"{seconds // 60}m"
        return f"{seconds}s"

    lines: list[str] = ["🧩 **Configured Spam Rules**"]
    for name_key, rule in sorted(guild_rules.items()):
        label = rule.get("label", name_key)
        min_length = rule.get("min_length", 0)
        similarity = float(rule.get("similarity_threshold", 0.0)) * 100
        message_count = rule.get("message_count", 0)
        window = _format_window(rule.get("time_window", 0))
        nonreply_only = _coerce_bool(rule.get("nonreply_only", False))

        notify_channel_id = rule.get("notify_channel_id")
        notify_channel = None
        if notify_channel_id:
            notify_channel = ctx.guild.get_channel(int(notify_channel_id))

        channels = rule.get("channels", set()) or set()
        if channels:
            channel_mentions = []
            for channel_id in sorted(channels):
                channel_obj = ctx.guild.get_channel(int(channel_id))
                if isinstance(channel_obj, discord.TextChannel):
                    channel_mentions.append(channel_obj.mention)
                else:
                    channel_mentions.append(f"`{channel_id}`")
            channels_text = ", ".join(channel_mentions)
        else:
            channels_text = "All text channels"

        notify_text = (
            notify_channel.mention
            if isinstance(notify_channel, discord.TextChannel)
            else (f"`{notify_channel_id}`" if notify_channel_id else "Not set")
        )

        lines.extend([
            f"\n**{label}** (`{name_key}`)",
            f"• Min characters: {min_length}",
            f"• Similarity: {similarity:.0f}%",
            f"• Threshold: {message_count} messages in {window}",
            f"• Mod-log channel: {notify_text}",
            f"• Scope: {channels_text}",
            f"• Count only non-replies: {'Yes' if nonreply_only else 'No'}",
        ])

        dm_message = rule.get("dm_message")
        if dm_message:
            preview = dm_message if len(dm_message) <= 120 else dm_message[:117] + "..."
            lines.append(f"• DM message: {preview}")

    messages: list[str] = []
    buffer: list[str] = []
    length = 0
    for line in lines:
        addition = len(line) + 1
        if buffer and length + addition > 1900:
            messages.append("\n".join(buffer))
            buffer = [line]
            length = len(line)
        else:
            buffer.append(line)
            length += addition

    if buffer:
        messages.append("\n".join(buffer))

    for chunk in messages:
        await ctx.send(chunk)

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
        await ctx.send("No-avatar filter disabled.")
    else:
        await ctx.send("Please type 'on' or 'off'.")
        return
    
    # Save settings
    save_security_settings()

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
        await ctx.send("Account age filter disabled.")
        # Save settings
        save_security_settings()
        return
    elif state == "on":
        if min_age is None or mode is None:
            await ctx.send("Please specify the minimum account age (in days) and a mode. Example: `!accountagefilter on 7 timeout 60`")
            return
        account_age_filter_enabled = True
        account_age_min_days = min_age
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
        
        # Save settings
        save_security_settings()
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
    
    # Save settings
    save_security_settings()
    
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
    
    # Save settings
    save_security_settings()
    
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
    guild_spam_rules = spam_rules_by_guild.get(ctx.guild.id, {})
    if guild_spam_rules:
        embed.add_field(name="Spam Rules", value=f"{len(guild_spam_rules)} configured", inline=False)
    else:
        embed.add_field(name="Spam Rules", value="No spam rules configured", inline=False)
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
        "   - Description: Authorizes the specified user or role ID for security commands (with validation and audit).\n\n"
        "4. **!securityauthorizedremove <id>**\n"
        "   - Description: Removes the specified user or role ID from the security authorized list (with audit).\n\n"
        "5. **!securitysettings**\n"
        "   - Description: Displays current security settings (filter statuses, actions, timeout durations, etc.).\n\n"
        "6. **!securityaudit [limit]**\n"
        "   - Description: Shows security audit log (default: 10 entries, max: 50).\n\n"
        "7. **!regex <regexsettingsname> <regex>**\n"
        "   - Description: Defines/updates a regex rule with the given name. Supports `/pattern/flags` or `pattern --flags imsx`. If the advanced `regex` engine is installed it is used; otherwise Python's built-in `re` is used.\n\n"
        "8. **!setregexsettings <regexsettingsname> <channels>**\n"
        "   - Description: Assigns which channels the regex rule applies to. You can specify multiple channels by ID or #mention.\n"
        "   - Also supported: `!setregexsettings <name> allchannel notchannel <channels_to_exclude>` → apply to all text channels except the ones listed after `notchannel`.\n\n"
        "9. **!setregexexempt <regexsettingsname> users|roles <targets>**\n"
        "   - Description: Sets users or roles exempt from the rule.\n\n"
        "10. **!regexsettings [regexsettingsname]**\n"
        "   - Description: Shows active regex rules and their details (channels and exemptions). Provide a name to see only that rule.\n\n"
        "11. **!delregexsettings <regexsettingsname>**\n"
        "   - Description: Deletes the specified regex setting from this server.\n\n"
        "12. **!spamrule <name> characters>... %... <duration> message>... dm <text> ...**\n"
        "   - Description: Creates or updates a spam rule that detects similar messages within a time window, DMs the user, and alerts moderators.\n"
        "   - Duration options include: `24h`, `7d`, `30d`, `60d`, `90d`, `120d`, `180d`, `360d`.\n"
        "   - Optional switches: `modlogchannel #channel` (or channel ID), `specchannel #ch1 #ch2`, `nonreply on|off` (add after the DM text, usually at the end; default: off). Inline forms like `nonreply=on` also work.\n"
        "   - Tip: Make sure the channel you mention after `modlogchannel` actually exists (or use its numeric ID). Keep `nonreply on|off` as the last switch.\n"
        "   - Examples:\n"
        "       • `!spamrule promo characters>40 %85 24h message>4 dm \"Please avoid repeating promotional messages.\" modlogchannel #modhub specchannel #general #announcements`\n"
        "       • `!spamrule replies characters>25 %80 24h message>3 dm \"Please avoid mass replying to threads.\" modlogchannel 123456789012345678 nonreply on` (replace the numbers with your mod-log channel ID)\n"
        "       • `!spamrule ads characters>20 %90 7d message>3 dm \"Advertising content is not allowed.\" modlogchannel #compliance specchannel #marketplace`\n"
        "       • `!spamrule flood characters>15 %75 24h message>5 dm \"Please stop flooding the chat.\" modlogchannel #security-alerts`\n\n"
        "13. **!removespamrule <name>**\n"
        "   - Description: Deletes the specified spam rule from this server.\n"
        "   - Example: `!removespamrule flood`\n\n"
        "14. **!spamrules**\n"
        "   - Description: Lists all configured spam rules with their thresholds and options.\n"
        "   - Example: `!spamrules`\n\n"
        "15. **!setverifyrole <role_id|@role>**\n"
        "   - Description: Sets the role to be assigned after successful CAPTCHA verification.\n"
        "   - Example: `!setverifyrole @Verified` → Sets the Verified role as the verification reward.\n\n"
        "16. **!sendverifypanel [#channel|channel_id]**\n"
        "   - Description: Sends a verification panel with CAPTCHA button to the specified channel (or current channel).\n"
        "   - Example: `!sendverifypanel #verification` → Sends verification panel to the verification channel.\n\n"
        "17. **!setverifypaneltext <title|description|image> <text|url>**\n"
        "   - Description: Customizes the verification panel title, description text, or image.\n"
        "   - Examples: `!setverifypaneltext title Welcome to Our Server` → Changes panel title.\n"
        "   - `!setverifypaneltext image https://example.com/logo.png` → Adds panel image.\n\n"
        "18. **!showverifypaneltext**\n"
        "   - Description: Shows the current verification panel text settings.\n\n"
        "19. **!resetverifypaneltext**\n"
        "   - Description: Resets verification panel text to default values.\n\n"
        "20. **!savesecurity**\n"
        "   - Description: Manually saves all security settings to file.\n\n"
        "21. **!securityhelp**\n"
        "   - Description: Shows this help menu.\n"
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

@bot.command(name="savesecurity")
async def savesecurity(ctx):
    if not is_security_authorized(ctx):
        await ctx.message.delete()
        return
    
    # Security: Rate limiting
    if await _handle_security_rate_limit(ctx, "savesecurity"):
        return
    
    # Manuel kaydetme
    success = save_security_settings()
    
    if success:
        embed = discord.Embed(
            title="✅ Security Settings Saved",
            description="All security settings have been successfully saved to file.",
            color=discord.Color.green()
        )
        
        # Show statistics
        stats = []
        if no_avatar_filter_enabled or account_age_filter_enabled:
            filters = []
            if no_avatar_filter_enabled:
                filters.append("No-Avatar")
            if account_age_filter_enabled:
                filters.append("Account Age")
            stats.append(f"**Active Filters:** {', '.join(filters)}")
        
        if security_authorized_ids:
            stats.append(f"**Authorized IDs:** {len(security_authorized_ids)}")
        
        if captcha_verify_role_id:
            stats.append(f"**Captcha Role:** Set")
        
        if captcha_panel_texts:
            stats.append(f"**Panel Texts:** {len(captcha_panel_texts)} guilds")
        
        if regex_settings_by_guild:
            total_rules = sum(len(rules) for rules in regex_settings_by_guild.values())
            stats.append(f"**Regex Rules:** {total_rules} rules in {len(regex_settings_by_guild)} guilds")
        
        if verify_button_usage:
            stats.append(f"**Verify Usage:** {len(verify_button_usage)} users tracked")
        
        if stats:
            embed.add_field(
                name="📊 Saved Settings Summary",
                value="\n".join(stats),
                inline=False
            )
        
        embed.add_field(
            name="📁 File Location",
            value=f"`{SECURITY_SETTINGS_FILE}`",
            inline=False
        )
        
        await ctx.send(embed=embed)
    else:
        embed = discord.Embed(
            title="❌ Save Failed",
            description="An error occurred while saving security settings. Check console for details.",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)

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
    # Load security settings from file
    print("[SECURITY] Loading security settings...")
    load_security_settings()

    print("[SECURITY] Loading spam violation statistics...")
    load_spam_violation_stats()
    
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
    
    # Save settings
    save_security_settings()
    
    await ctx.send(f"Verification role set: {role.mention} ({rid})")


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
    
    # Save settings
    save_security_settings()
    
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
    
    # Save settings
    save_security_settings()
    
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
bot.run(bot_token)
