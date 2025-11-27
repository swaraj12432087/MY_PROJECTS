#!/usr/bin/env python3
"""
Real-Time Chat Server using WebSockets with Authentication and Persistent Storage
Compatible with websockets library versions 10.0+ and 13.0+
Supports user registration, login with passwords, persistent message history and file storage
"""

import asyncio
import websockets
import json
import hashlib
import secrets
import os
from datetime import datetime
from collections import defaultdict

# Check websockets version to use correct handler signature
WEBSOCKETS_VERSION = tuple(map(int, websockets.__version__.split('.')[:2]))
print(f"WebSockets version: {websockets.__version__}")

# File paths for persistent storage
HISTORY_FILE = "chat_history.json"
USERS_FILE = "users.json"

# Store connected clients: {websocket: username}
clients = {}

# Store user credentials: {username: {"password_hash": hash, "salt": salt}}
users_db = {}

# Store messages for offline delivery: {username: [messages]}
offline_messages = defaultdict(list)

# Store chat history: {(user1, user2): [messages]}
chat_history = defaultdict(list)

# Store all registered users (even offline ones)
all_registered_users = set()

# Maximum messages to store per conversation
MAX_HISTORY = 100

# Store user status: {username: "online"/"offline"}
user_status = {}

# Store session tokens: {token: username}
sessions = {}


def load_data():
    """Load chat history and users from files"""
    global chat_history, users_db, all_registered_users
    
    # Load users database
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                users_db.update(json.load(f))
            all_registered_users = set(users_db.keys())
            print(f"✓ Loaded {len(users_db)} registered users")
        except Exception as e:
            print(f"✗ Error loading users: {e}")
    
    # Load chat history
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                data = json.load(f)
                # Convert string keys back to tuples
                for key_str, messages in data.items():
                    users = tuple(json.loads(key_str))
                    chat_history[users] = messages
            total_messages = sum(len(msgs) for msgs in chat_history.values())
            print(f"✓ Loaded {len(chat_history)} conversations ({total_messages} messages)")
        except Exception as e:
            print(f"✗ Error loading chat history: {e}")


def save_data():
    """Save chat history and users to files"""
    try:
        # Save users database
        with open(USERS_FILE, 'w') as f:
            json.dump(users_db, f, indent=2)
        
        # Save chat history
        data = {}
        for key, messages in chat_history.items():
            # Convert tuple to string for JSON
            key_str = json.dumps(sorted(key))
            data[key_str] = messages
        
        with open(HISTORY_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save data: {e}")
        return False


def get_chat_key(user1, user2):
    """Get consistent key for chat history between two users"""
    return tuple(sorted([user1, user2]))


def store_message(sender, recipient, text, timestamp):
    """Store message in chat history and save to file"""
    key = get_chat_key(sender, recipient)
    
    msg = {
        "from": sender,
        "to": recipient,
        "text": text,
        "timestamp": timestamp
    }
    
    chat_history[key].append(msg)
    
    # Keep only last MAX_HISTORY messages
    if len(chat_history[key]) > MAX_HISTORY:
        chat_history[key] = chat_history[key][-MAX_HISTORY:]
    
    # Save to file
    save_data()


def get_chat_history(user1, user2):
    """Get chat history between two users"""
    key = get_chat_key(user1, user2)
    return chat_history.get(key, [])


def hash_password(password, salt=None):
    """Hash a password with salt using SHA-256"""
    if salt is None:
        salt = secrets.token_hex(16)
    
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return pwd_hash, salt


def verify_password(username, password):
    """Verify if password matches stored hash"""
    if username not in users_db:
        return False
    
    stored_hash = users_db[username]["password_hash"]
    salt = users_db[username]["salt"]
    
    pwd_hash, _ = hash_password(password, salt)
    
    return pwd_hash == stored_hash


def register_user(username, password):
    """Register a new user and save to file"""
    if username in users_db:
        return False, "Username already exists"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    
    if len(password) < 4:
        return False, "Password must be at least 4 characters"
    
    # Hash password and store
    pwd_hash, salt = hash_password(password)
    users_db[username] = {
        "password_hash": pwd_hash,
        "salt": salt,
        "created": datetime.now().isoformat()
    }
    
    all_registered_users.add(username)
    
    # Save to file
    save_data()
    
    print(f"[REG] New user registered: {username}")
    return True, "Registration successful"


def login_user(username, password):
    """Login user and create session"""
    if not verify_password(username, password):
        return False, None, "Invalid username or password"
    
    # Create session token
    token = secrets.token_urlsafe(32)
    sessions[token] = username
    
    print(f"[LOGIN] User logged in: {username}")
    return True, token, "Login successful"


def verify_session(token):
    """Verify if session token is valid"""
    return sessions.get(token)


async def register_connection(websocket, username):
    """Register a new client connection"""
    clients[websocket] = username
    user_status[username] = "online"
    print(f"[+] {username} connected. Total users: {len(clients)}")
    
    # Send offline messages if any
    if username in offline_messages and offline_messages[username]:
        for msg in offline_messages[username]:
            try:
                await websocket.send(json.dumps(msg))
            except Exception as e:
                print(f"[ERROR] Failed to send offline message: {e}")
        offline_messages[username].clear()
    
    # Notify all users about new user
    await broadcast_user_list()


async def unregister(websocket):
    """Unregister a client connection"""
    if websocket in clients:
        username = clients[websocket]
        del clients[websocket]
        user_status[username] = "offline"
        print(f"[-] {username} disconnected. Total users: {len(clients)}")
        
        # Notify all users about user leaving
        await broadcast_user_list()


async def broadcast_user_list():
    """Send updated user list to all connected clients"""
    # Include ALL registered users with their status
    all_users = []
    
    # Add online users
    for username in clients.values():
        all_users.append({
            "username": username,
            "status": "online"
        })
    
    # Add offline registered users
    for username in all_registered_users:
        if username not in [u["username"] for u in all_users]:
            all_users.append({
                "username": username,
                "status": "offline"
            })
    
    message = {
        "type": "user_list",
        "users": all_users,
        "timestamp": datetime.now().isoformat()
    }
    
    # Send to all connected clients
    if clients:
        disconnected = []
        for client in clients.keys():
            try:
                await client.send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                disconnected.append(client)
            except Exception as e:
                print(f"[ERROR] Failed to send user list: {e}")
        
        # Clean up disconnected clients
        for client in disconnected:
            await unregister(client)


async def handle_message(websocket, data):
    """Handle incoming messages from clients"""
    try:
        message = json.loads(data)
        msg_type = message.get("type")
        
        if msg_type == "register":
            # Handle user registration
            username = message.get("username")
            password = message.get("password")
            
            success, result = register_user(username, password)
            
            response = {
                "type": "register_response",
                "success": success,
                "message": result,
                "timestamp": datetime.now().isoformat()
            }
            await websocket.send(json.dumps(response))
            
        elif msg_type == "login":
            # Handle user login
            username = message.get("username")
            password = message.get("password")
            
            success, token, result = login_user(username, password)
            
            if success:
                await register_connection(websocket, username)
                response = {
                    "type": "login_response",
                    "success": True,
                    "token": token,
                    "username": username,
                    "message": result,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                response = {
                    "type": "login_response",
                    "success": False,
                    "message": result,
                    "timestamp": datetime.now().isoformat()
                }
            
            await websocket.send(json.dumps(response))
            
        elif msg_type == "get_history":
            # Handle chat history request
            sender = clients.get(websocket)
            other_user = message.get("with")
            
            if not sender or not other_user:
                return
            
            history = get_chat_history(sender, other_user)
            
            response = {
                "type": "history",
                "with": other_user,
                "messages": history,
                "timestamp": datetime.now().isoformat()
            }
            
            await websocket.send(json.dumps(response))
            print(f"[HISTORY] Sent {len(history)} messages for {sender} <-> {other_user}")
            
        elif msg_type == "message":
            # Handle direct message (requires authentication)
            sender = clients.get(websocket)
            if not sender:
                error = {
                    "type": "error",
                    "message": "Not authenticated",
                    "timestamp": datetime.now().isoformat()
                }
                await websocket.send(json.dumps(error))
                return
            
            recipient = message.get("to")
            text = message.get("text")
            
            if not recipient or not text:
                return
            
            timestamp = datetime.now().isoformat()
            
            # Store message in history (and save to file)
            store_message(sender, recipient, text, timestamp)
            
            msg_data = {
                "type": "message",
                "from": sender,
                "to": recipient,
                "text": text,
                "timestamp": timestamp
            }
            
            # Find recipient's websocket
            recipient_ws = None
            for ws, username in clients.items():
                if username == recipient:
                    recipient_ws = ws
                    break
            
            # Send to recipient if online
            if recipient_ws:
                try:
                    await recipient_ws.send(json.dumps(msg_data))
                    print(f"[MSG] {sender} -> {recipient}: {text[:50]}")
                except websockets.exceptions.ConnectionClosed:
                    offline_messages[recipient].append(msg_data)
                    print(f"[OFFLINE] {sender} -> {recipient}: {text[:50]}")
                except Exception as e:
                    print(f"[ERROR] Failed to send message: {e}")
            else:
                offline_messages[recipient].append(msg_data)
                print(f"[OFFLINE] {sender} -> {recipient}: {text[:50]}")
            
            # Send confirmation to sender
            try:
                confirmation = {
                    "type": "sent",
                    "to": recipient,
                    "text": text,
                    "timestamp": timestamp
                }
                await websocket.send(json.dumps(confirmation))
            except Exception as e:
                print(f"[ERROR] Failed to send confirmation: {e}")
            
        elif msg_type == "typing":
            # Handle typing indicator
            sender = clients.get(websocket)
            recipient = message.get("to")
            
            if not sender or not recipient:
                return
            
            for ws, username in clients.items():
                if username == recipient:
                    try:
                        typing_msg = {
                            "type": "typing",
                            "from": sender,
                            "timestamp": datetime.now().isoformat()
                        }
                        await ws.send(json.dumps(typing_msg))
                    except Exception as e:
                        print(f"[ERROR] Failed to send typing indicator: {e}")
                    break
                    
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON received: {e}")
    except Exception as e:
        print(f"[ERROR] Error handling message: {e}")


async def handler_new(websocket):
    """Handler for websockets library version 13.0+"""
    try:
        print(f"[*] New connection from {websocket.remote_address}")
    except:
        print(f"[*] New connection")
    
    try:
        async for message in websocket:
            await handle_message(websocket, message)
    except websockets.exceptions.ConnectionClosedOK:
        print(f"[*] Connection closed normally")
    except websockets.exceptions.ConnectionClosedError as e:
        print(f"[!] Connection closed with error: {e}")
    except Exception as e:
        print(f"[ERROR] Handler error: {e}")
    finally:
        await unregister(websocket)


async def handler_old(websocket, path):
    """Handler for websockets library version 10.0-12.x"""
    try:
        print(f"[*] New connection from {websocket.remote_address} (path: {path})")
    except:
        print(f"[*] New connection (path: {path})")
    
    try:
        async for message in websocket:
            await handle_message(websocket, message)
    except websockets.exceptions.ConnectionClosedOK:
        print(f"[*] Connection closed normally")
    except websockets.exceptions.ConnectionClosedError as e:
        print(f"[!] Connection closed with error: {e}")
    except Exception as e:
        print(f"[ERROR] Handler error: {e}")
    finally:
        await unregister(websocket)


async def main():
    """Start the WebSocket server"""
    host = "0.0.0.0"
    port = 8765
    
    print("=" * 50)
    print("🚀 Authenticated Chat Server Starting...")
    print("=" * 50)
    
    # Load existing data
    load_data()
    
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"WebSocket URL: ws://localhost:{port}")
    print("=" * 50)
    
    try:
        if WEBSOCKETS_VERSION >= (13, 0):
            print(f"Using new API (websockets {websockets.__version__})")
            print("🔐 Authentication enabled")
            print("💾 File storage enabled")
            print("Server is running. Press Ctrl+C to stop.\n")
            async with websockets.serve(
                handler_new,
                host,
                port,
                ping_interval=20,
                ping_timeout=10
            ):
                await asyncio.Future()
        else:
            print(f"Using old API (websockets {websockets.__version__})")
            print("🔐 Authentication enabled")
            print("💾 File storage enabled")
            print("Server is running. Press Ctrl+C to stop.\n")
            async with websockets.serve(
                handler_old,
                host,
                port,
                ping_interval=20,
                ping_timeout=10
            ):
                await asyncio.Future()
                
    except OSError as e:
        if e.errno == 98:
            print(f"\n[ERROR] Port {port} is already in use!")
            print("Try: sudo lsof -ti:{port} | xargs kill -9")
        else:
            print(f"\n[ERROR] Failed to start server: {e}")
    except Exception as e:
        print(f"\n[ERROR] Server error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n[!] Server stopped by user")
        print(f"Total registered users: {len(users_db)}")
        print(f"Total conversations: {len(chat_history)}")
        total_messages = sum(len(msgs) for msgs in chat_history.values())
        print(f"Total messages: {total_messages}")
        print(f"Data saved to: {USERS_FILE}, {HISTORY_FILE}")
    except Exception as e:
        print(f"\n[ERROR] Server crashed: {e}")
        import traceback
        traceback.print_exc()
