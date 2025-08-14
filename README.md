# Discord Security and Verification Bot

## Description
This bot provides comprehensive security measures and CAPTCHA-based verification for Discord servers. It automatically filters users, blocks unwanted messages, and offers a secure verification process for new members.

## Features

### Security Filters
- **Avatar Filter**: Automatically ban, kick, or timeout users without avatars
- **Account Age Filter**: Apply automatic actions based on account creation date
- **Flexible Actions**: Choose between ban, kick, or timeout for each filter
- **Customizable Timeouts**: Set timeout durations in minutes

### Message Moderation
- **Regex-Based Filtering**: Automatically delete messages using custom regex patterns
- **Channel-Specific Rules**: Apply different regex rules to different channels
- **Exemption Management**: Exclude specific users and roles from rules
- **Advanced Regex Engine**: Supports both standard `re` and enhanced `regex` modules

### Verification System
- **CAPTCHA Verification**: Visual or text-based CAPTCHA challenges
- **Customizable Verification Panel**: Modify title, description, and image
- **Automatic Role Assignment**: Grant roles after successful verification
- **Rate Limiting**: Limit CAPTCHA requests per minute
- **Attempt Limits**: Restrict maximum verification attempts per user

### Management Tools
- **Security Authorization**: Role-based and user-based authorization for security commands
- **Settings Management**: View and modify all security settings
- **Comprehensive Help System**: Detailed help menu for all commands

## Installation

### Requirements
- Python 3.8+
- Discord.py
- PIL (Pillow) - For CAPTCHA images
- python-dotenv
- regex (optional, for advanced regex engine)

