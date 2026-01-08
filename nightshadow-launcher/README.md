# NightShadow Launcher

A Matrix-themed launcher for NightShadow that connects to zon-productions.com for authentication and game downloads.

## Features

- Login with zon-productions.com account
- View game status and update info
- Download game with progress bar
- Auto-extract game files
- Launch game directly
- Remember login credentials

## Building the Launcher

### Prerequisites

- Python 3.8+
- pip

### Build Steps

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Build executable:
   ```bash
   pyinstaller --onefile --windowed --name "NightShadow Launcher" launcher.py
   ```

3. The executable will be in `dist/NightShadow Launcher.exe`

### With Icon (optional)

1. Add an `icon.ico` file to this directory
2. Build with:
   ```bash
   pyinstaller --onefile --windowed --name "NightShadow Launcher" --icon=icon.ico launcher.py
   ```

## Usage

1. Run the launcher
2. Login with your zon-productions.com credentials
3. Click [DOWNLOAD] to download the game
4. Click [PLAY] to launch the game

## File Locations

| Item | Location |
|------|----------|
| Config | `~/.nightshadow/config.json` |
| Game Files | `~/.nightshadow/game/` |

## API Endpoints Used

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/login` | POST | Authenticate user |
| `/api/game-info` | GET | Get game file info |
| `/api/download` | POST | Download game (requires auth) |

## Configuration

The launcher stores credentials locally in `~/.nightshadow/config.json`. 

To change the server URL, edit `API_URL` in `launcher.py`:
```python
API_URL = "https://zon-productions.com"
```

## Troubleshooting

### "Cannot connect to server"
- Check your internet connection
- Verify zon-productions.com is accessible

### "Account pending approval"
- Your account needs admin approval
- Wait for admin to approve, then try again

### "Invalid credentials"
- Check email and password
- Try logging in on the website first

### Game won't launch
- Check `~/.nightshadow/game/` for the game files
- Look for the game executable manually
