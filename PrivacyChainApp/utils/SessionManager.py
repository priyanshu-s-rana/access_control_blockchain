import time
import os
import json
import atexit
import signal
from ..dynamic_accumulator import RsaAccumulator
class SessionManager:
    _instance = None
    # Store the json file in the same directory as SessionManager.py
    _session_file = os.path.join(os.path.dirname(__file__), 'sessions.json')

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SessionManager, cls).__new__(cls)
            cls._instance._sessions = {}  # Initialize as an instance variable
            cls._instance._load_sessions()
            # Register cleanup handlers for different shutdown scenarios
            # atexit.register(cls._instance._cleanup_on_exit)
            signal.signal(signal.SIGINT, cls._instance._signal_handler)
            signal.signal(signal.SIGTERM, cls._instance._signal_handler)
        return cls._instance

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self._cleanup_on_exit()
        # Re-raise the signal to allow the program to terminate
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    def _cleanup_on_exit(self):
        """Cleanup method that runs when the server shuts down"""
        try:
            if os.path.exists(self._session_file):
                os.remove(self._session_file)
                print(f"Session file {self._session_file} removed during shutdown")
        except Exception as e:
            print(f"Error removing session file {self._session_file} during shutdown: {e}")

    def _load_sessions(self):
        """Load sessions from a JSON file."""
        if os.path.exists(self._session_file):
            try:
                with open(self._session_file, 'r') as f:
                    # Load JSON and convert accumulator objects to their string representation
                    raw_sessions = json.load(f)
                    self._sessions = self._deserialize_sessions(raw_sessions)
            except Exception as e:
                print(f"Error loading sessions from {self._session_file}: {e}. Initializing with empty sessions.")
                self._sessions = {}
        else:
            self._sessions = {}

    def _save_sessions(self):
        """Save current sessions to a JSON file."""
        try:
            # Convert accumulator objects to serializable format
            serialized_sessions = self._serialize_sessions(self._sessions)
            with open(self._session_file, 'w') as f:
                json.dump(serialized_sessions, f, indent=2)
        except Exception as e:
            print(f"Error saving sessions to {self._session_file}: {e}")

    def _serialize_sessions(self, sessions):
        """Convert session data to JSON-serializable format"""
        serialized = {}
        for session_id, session_data in sessions.items():
            serialized[session_id] = session_data.copy()
            # Convert accumulator objects to string representations
            if 'acc' in serialized[session_id] and isinstance(serialized[session_id]['acc'], RsaAccumulator):
                serialized[session_id]['acc'] = serialized[session_id]['acc'].to_dict()
                
            if 'ds_file_acc' in serialized[session_id] and isinstance(serialized[session_id]['ds_file_acc'], RsaAccumulator):
                serialized[session_id]['ds_file_acc'] = serialized[session_id]['ds_file_acc'].to_dict()
                
            if 'ids_file_acc' in serialized[session_id] and isinstance(serialized[session_id]['ids_file_acc'], RsaAccumulator):
                serialized[session_id]['ids_file_acc'] = serialized[session_id]['ids_file_acc'].to_dict()
        return serialized

    def _deserialize_sessions(self, serialized_sessions):
        """Convert JSON data back to session format"""
        # Note: Accumulator objects should be recreated from blockchain data
        # This is just a placeholder that keeps the string representation
        deserialized = {}
        for session_id, session_data in serialized_sessions.items():
            deserialized[session_id] = session_data.copy()
            
            # Handle the main accumulator
            if 'acc' in deserialized[session_id] and isinstance(deserialized[session_id]['acc'], dict):
                deserialized[session_id]['acc'] = RsaAccumulator.from_dict(deserialized[session_id]['acc'])
            
            # Handle direct_access accumulator
            if 'ds_file_acc' in deserialized[session_id]:
                if isinstance(deserialized[session_id]['ds_file_acc'], dict):
                    deserialized[session_id]['ds_file_acc'] = RsaAccumulator.from_dict(deserialized[session_id]['ds_file_acc'])
            
            # Handle indirect_access accumulator
            if 'ids_file_acc' in deserialized[session_id]:
                if isinstance(deserialized[session_id]['ids_file_acc'], dict):
                    deserialized[session_id]['ids_file_acc'] =  RsaAccumulator.from_dict(deserialized[session_id]['ids_file_acc'])
        
        return deserialized

    def get_session(self, session_id: str) -> dict:
        """Get session data for a session ID"""
        session_data = self._sessions.get(session_id)
        if session_data:
            # Convert accumulator objects back to their original form
            if 'acc' in session_data and isinstance(session_data['acc'], dict):
                session_data['acc'] = RsaAccumulator.from_dict(session_data['acc'])
            if 'ds_file_acc' in session_data and isinstance(session_data['ds_file_acc'], dict):
                session_data['ds_file_acc'] = RsaAccumulator.from_dict(session_data['ds_file_acc'])
            if 'ids_file_acc' in session_data and isinstance(session_data['ids_file_acc'], dict):
                session_data['ids_file_acc'] = RsaAccumulator.from_dict(session_data['ids_file_acc'])
        return session_data

    def create_session(self, session_id: str, user_data: dict):
        """Create or update a session"""
        print(f"Creating session : ", user_data)
        if session_id not in self._sessions :
            self._sessions[session_id] = user_data
        # self._sessions[session_id] = user_data
        else :
            if user_data['usertype'] != 'Data Owner':
                self._sessions[session_id]['ids_file_acc'] = user_data['ids_file_acc']
                self._sessions[session_id]['ds_file_acc'] = user_data['ds_file_acc']
            self._sessions[session_id]['acc'] = user_data['acc']
            arr1 = self._sessions[session_id]['runtime_data']
            arr2 = user_data['runtime_data']
            self._sessions[session_id]['runtime_data'] = list(set(arr1+arr2))
            self._sessions[session_id]['login_time'] = user_data['login_time']
        self._save_sessions()

    def delete_session(self, session_id: str):
        """Remove a session"""
        if session_id in self._sessions:
            del self._sessions[session_id]
            self._save_sessions()

    def cleanup_expired_sessions(self, max_age: int = 24*3600):
        """Remove sessions older than max_age seconds"""
        current_time = time.time()
        expired_session_ids = [
            sid for sid, data in self._sessions.items()
            if current_time - data.get('login_time', 0) > max_age
        ]
        
        if expired_session_ids:
            for session_id in expired_session_ids:
                if session_id in self._sessions:
                    del self._sessions[session_id]
            self._save_sessions()

    def get_users_by_role(self, role: str) -> list:
        """Get all users of a specific role"""
        return [
            {'username': data['username']}
            for data in self._sessions.values()
            if data.get('usertype') == role
        ]

    def get_user_by_name(self, username: str) -> dict:
        """Get user data by username"""
        for session_data in self._sessions.values():
            if session_data.get('username') == username:
                return session_data
        return None
    
    def get_usernames_by_ids(self, user_ids: list) -> list:
        usernames = []
        for user in self._sessions.values():
            if user['user_id'] in user_ids and user['username'] not in usernames:
                usernames.append(user['username'])
                
        return usernames

    def get_all_sessions(self) -> dict:
        """Get all active sessions (returns a copy)"""
        return self._sessions.copy()

# Create a singleton instance
session_manager = SessionManager()