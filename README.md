# Discord Security Bot - Installation and Requirements

## 📋 Overview

This Discord bot is an advanced moderation bot that offers comprehensive security features for your server. The bot includes new member filtering, regex-based message moderation, CAPTCHA verification system, and detailed security settings.

## 🔧 System Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux, Windows, macOS
- **RAM**: Minimum 512MB (recommended 1GB)
- **Disk Space**: 100MB

## 📦 Installation

### Recommended Installation (One Command)

```bash
# Install all dependencies at once
pip install -r requirements.txt
```

This single command will install all required and optional dependencies for full functionality.

### What Gets Installed

#### Core Dependencies (Required)
- **discord.py>=2.0.0** - Main Discord bot framework
- **python-dotenv>=0.19.0** - Environment variable support (.env files)

#### Optional Dependencies (Recommended)
- **Pillow>=8.0.0** - Advanced CAPTCHA image generation
- **regex>=2021.0.0** - Enhanced regex engine (faster than built-in `re`)

### Manual Installation (If Needed)

```bash
# Install only core dependencies (basic functionality)
pip install discord.py>=2.0.0 python-dotenv>=0.19.0

# Add optional features
pip install Pillow>=8.0.0 regex>=2021.0.0
```

## Quick Setup

### 1. Install Dependencies

```bash
# Install all dependencies (recommended)
pip install -r requirements.txt
```

**Alternative**: Manual installation
```bash
# Core only (basic functionality)
pip install discord.py>=2.0.0 python-dotenv>=0.19.0

# Full features (recommended)
pip install discord.py>=2.0.0 python-dotenv>=0.19.0 Pillow>=8.0.0 regex>=2021.0.0
```

### 2. Set Bot Token

Create a `.env` file:

```env
# Bot token (obtained from Discord Developer Portal)
PLAYBOT=your_bot_token_here

# Security manager role ID (optional)
SECURITY_MANAGER_ROLE_ID=your_security_role_id_here



### 3. Run the Bot

```bash
python3 lastsecurity.py
```

## 🔐 Discord Bot Setup

### Creating a Bot

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application" button
3. Enter bot name and click "Create" button
4. Go to "Bot" tab from left menu
5. Click "Add Bot" button
6. Copy your bot token from "Token" section

### Bot Permissions

The bot requires the following permissions to function properly:

- Read Messages/View Channels
- Send Messages
- Manage Messages
- Kick Members
- Ban Members
- Manage Roles
- Moderate Members (Timeout)
- Use Slash Commands

### Adding to Server

1. Go to "OAuth2" > "URL Generator" tab in Developer Portal
2. Select `bot` and `applications.commands` from "Scopes" section
3. Select the above permissions from "Bot Permissions" section
4. Copy the generated URL and add to your server

## ⚙️ Configuration

### Environment Variables

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `PLAYBOT` | ✅ | Discord bot token | - |
| `SECURITY_MANAGER_ROLE_ID` | ❌ | Default security manager role ID | 0 |
| `DEBUG_MODE` | ❌ | Debug mode (true/false) | false |

### Initial Setup Steps

1. **Add Security Manager**:
   ```
   !securityauthorizedadd @YourRole
   ```
   or
   ```
   !securityauthorizedadd 123456789012345678
   ```

2. **Set Verification Role** (for CAPTCHA):
   ```
   !setverifyrole @Verified
   ```

3. **Activate Security Filters**:
   ```
   # Avatar control
   !noavatarfilter on timeout 60

   # Account age control
   !accountagefilter on 7 timeout 120
   ```

## 🛡 Features and Commands

### Security Filters

#### Avatar Filter
- Automatically filters new members without avatars
- Actions: ban, kick, timeout
```bash
!noavatarfilter on timeout 60  # 60 minute timeout
!noavatarfilter off             # Disable filter
```

#### Account Age Filter
- Filters accounts younger than specified days
- Actions: ban, kick, timeout
```bash
!accountagefilter on 7 timeout 120  # 120 min timeout for accounts < 7 days
!accountagefilter off                # Disable filter
```

### Regex Moderation

#### Creating Regex Rules
```bash
# Simple pattern
!regex spamrule (discord\.gg|discordapp\.com)

# With flags
!regex spamrule /discord\.gg/i

# Advanced flags
!regex spamrule bad_words --flags i m s
```

#### Channel Assignment
```bash
# Specific channels
!setregexsettings spamrule #general #chat

# All channels (except some)
!setregexsettings spamrule allchannel notchannel #mod-log #admin
```

#### Setting Exemptions
```bash
# User exemption
!setregexexempt spamrule users @admin @moderator

# Role exemption
!setregexexempt spamrule roles @Staff @VIP
```

### CAPTCHA Verification

#### Sending Panel
```bash
!sendverifypanel #verification
```

#### Customizing Panel Text
```bash
!setverifypaneltext title "Welcome to Our Server"
!setverifypaneltext description "Verification required for access."
!setverifypaneltext image https://example.com/logo.png
```

### Security Management

#### Authorization
```bash
!securityauthorizedadd @SecurityRole    # Add role
!securityauthorizedadd 123456789012345  # Add by ID
!securityauthorizedremove @SecurityRole # Remove
```

#### Viewing Settings
```bash
!securitysettings    # All security settings
!regexsettings       # Regex rules
!securityaudit 20    # Last 20 security operations
```

## 🔍 Security Features

### Rate Limiting
- **Security Commands**: 5 commands per minute
- **CAPTCHA Requests**: 3 requests per minute
- **Verification Attempts**: 10 attempts per user

### Audit Logging
- All security operations are logged
- Last 100 operations are stored
- Timestamp and executor information

### ReDoS Protection
- Timeout protection in regex engine
- Maximum text length limit
- Thread-based safe regex search

## 🐛 Troubleshooting

### Common Errors

#### "Bot token not found"
```bash
# Check .env file
echo $PLAYBOT

# Set token manually
export PLAYBOT='your_token_here'
```

#### "Permission denied" errors
- Ensure bot has required permissions on server
- Check role hierarchy (bot role must be above target roles)

#### PIL/Pillow errors
```bash
# Ubuntu/Debian
sudo apt-get install python3-pil python3-pil.imagetk

# Using pip
pip install --upgrade Pillow
```

#### Font errors (Linux)
```bash
# Install DejaVu fonts
sudo apt-get install fonts-dejavu fonts-dejavu-core fonts-dejavu-extra
```

### Debug Mode

To activate debug mode:
```env
DEBUG_MODE=true
```

This mode provides additional information:
- Detailed URL validation information
- CAPTCHA generation logs
- PIL import status
- Regex engine information

## 📊 Performance Tips

### Optimization

1. **Regex Performance**:
   - Install `regex` package (faster than Python's `re` module)
   - Avoid complex patterns
   - Use exemptions wisely

2. **Memory Usage**:
   - Settings are automatically saved to file
   - Audit log is limited to 100 entries
   - Rate limit data is automatically cleaned

3. **CAPTCHA Performance**:
   - Simple text CAPTCHA is used if PIL is not installed
   - Font files are automatically found from system paths

##  Updates and Maintenance

### Backing Up Settings

Settings are automatically saved to `security_settings.json` file. For manual saving:
```bash
!savesecurity
```

### Restoring Settings

Settings are automatically loaded when bot starts. If manual loading is needed, restart the bot.

### Log Cleanup

Audit logs are automatically limited to 100 entries. Old entries are automatically deleted.

### Command Help
```bash
!securityhelp  # List of all commands
```

### Status Check
```bash
!securitysettings  # Current settings
!regexsettings     # Regex rules
!securityaudit     # Recent operations
```

### Log Monitoring

Bot shows important information in console output:
- PIL status
- Regex engine information
- Security operation logs
- Error messages

## 🎯 Usage Examples

### Basic Security Setup

```bash
# 1. Authorize yourself
!securityauthorizedadd @SecurityManager

# 2. Activate basic filters
!noavatarfilter on timeout 30
!accountagefilter on 7 kick

# 3. Add spam protection
!regex antispam (discord\.gg|t\.me|bit\.ly)
!setregexsettings antispam allchannel notchannel #links-allowed

# 4. Setup CAPTCHA system
!setverifyrole @Verified
!sendverifypanel #verification
```

## 📈 Monitoring and Statistics

The bot tracks the following statistics:

- **Rate Limit Usage**: Command frequency per user
- **CAPTCHA Statistics**: Verification attempt counts
- **Audit Log**: Security operation history
- **Filter Statistics**: Number of filtered members

You can access this information with the `!securitysettings` command.

## 🔧 Troubleshooting Guide

### Bot Not Working

1. **Token Check**:
   ```bash
   echo $PLAYBOT  # Linux/macOS
   echo %PLAYBOT% # Windows
   ```

2. **Permission Check**: Ensure bot has sufficient permissions on server

3. **Python Version**:
   ```bash
   python --version  # Should be 3.8+
   ```

### Commands Not Working

1. **DM Check**: Commands only work in servers
2. **Authorization Check**: Grant authorization with `!securityauthorizedadd`
3. **Rate Limit**: Don't use commands too quickly

### CAPTCHA Issues

1. **PIL Installation**:
   ```bash
   pip install Pillow
   ```

2. **Font Issues** (Linux):
   ```bash
   sudo apt-get install fonts-dejavu
   ```

3. **Role Hierarchy**: Bot role must be above roles it assigns

### Regex Issues

1. **Pattern Testing**: Use online regex testing tools
2. **Timeout Errors**: Avoid overly complex patterns
3. **Encoding**: Use `u` flag for Unicode characters

## 📚 Advanced Usage

### Custom Configuration

```python
# Modifiable settings in lastsecurity.py file:

MAX_SECURITY_AUTHORIZED_USERS = 4    # Maximum authorized users
SECURITY_COMMAND_RATE_LIMIT = 5      # Commands per minute limit
CAPTCHA_RATE_LIMIT = 3               # CAPTCHA requests per minute
VERIFY_MAX_ATTEMPTS = 10             # Maximum verification attempts
```

### Custom Panel Design

```bash
# Title customization
!setverifypaneltext title "🔐 Security Verification"

# Description customization
!setverifypaneltext description "Please click the button below and solve the CAPTCHA to access the server."

# Add image
!setverifypaneltext image https://your-server.com/logo.png
```

### Bulk Settings Management

```bash
# Save all settings
!savesecurity

# View settings
!securitysettings
!regexsettings
!showverifypaneltext
```

## 🔄 Updates and Maintenance

### Regular Maintenance

1. **Log Monitoring**: Regularly check console output
2. **Settings Backup**: Backup `security_settings.json` file
3. **Rate Limit Monitoring**: Check for excessive usage

### Bot Updates

1. Update bot file
2. Install new dependencies
3. Restart bot
4. Verify settings are preserved


### Command Help
```bash
!securityhelp  # Detailed list of all commands
```

### Status Information
```bash
!securitysettings  # Current security settings
!securityaudit     # Recent security operations
```


