"""
Configuration Manager Module
Handles application settings and preferences
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
import platform

class ConfigManager:
    """Manages application configuration and settings"""
    
    def __init__(self):
        self.config_dir = self._get_config_dir()
        self.config_file = self.config_dir / "config.json"
        self.config = self._load_config()
    
    def _get_config_dir(self) -> Path:
        """Get appropriate configuration directory based on OS"""
        system = platform.system()
        
        if system == "Windows":
            # Use AppData/Local on Windows
            base = Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local'))
            config_dir = base / 'EmailForensics'
        elif system == "Darwin":  # macOS
            # Use ~/Library/Application Support on macOS
            config_dir = Path.home() / 'Library' / 'Application Support' / 'EmailForensics'
        else:  # Linux and others
            # Use XDG_CONFIG_HOME or ~/.config on Linux
            xdg_config = os.environ.get('XDG_CONFIG_HOME')
            if xdg_config:
                config_dir = Path(xdg_config) / 'email-forensics'
            else:
                config_dir = Path.home() / '.config' / 'email-forensics'
        
        # Create directory if it doesn't exist
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        default_config = self._get_default_config()
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    # Merge with defaults
                    default_config.update(user_config)
            except Exception as e:
                print(f"Error loading config: {e}")
        
        return default_config
    
    def _get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            # UI Settings
            'dark_mode': True,
            'font_size': 10,
            'font_family': 'Segoe UI',
            'window_geometry': None,
            'last_directory': str(Path.home()),
            
            # API Keys
            'ipinfo_api_key': '',
            'virustotal_api_key': '',
            'abuseipdb_api_key': '',
            
            # Features
            'clipboard_monitor': False,
            'auto_analyze': False,
            'check_blacklists': True,
            'resolve_ptr': True,
            'cache_dns': True,
            'cache_ip_info': True,
            
            # Network
            'dns_timeout': 3,
            'http_timeout': 5,
            'max_retries': 2,
            'use_proxy': False,
            'proxy_settings': {
                'http': '',
                'https': ''
            },
            
            # Export Settings
            'export_format': 'pdf',
            'include_raw_headers': False,
            'include_timestamps': True,
            
            # Advanced
            'debug_mode': False,
            'log_level': 'INFO',
            'max_cache_size_mb': 100,
            'cache_expiry_days': 7
        }
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        self.config[key] = value
        self.save_config()
    
    def update(self, updates: Dict):
        """Update multiple configuration values"""
        self.config.update(updates)
        self.save_config()
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self._get_default_config()
        self.save_config()
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service"""
        key_map = {
            'ipinfo': 'ipinfo_api_key',
            'virustotal': 'virustotal_api_key',
            'abuseipdb': 'abuseipdb_api_key'
        }
        
        config_key = key_map.get(service.lower())
        if config_key:
            api_key = self.config.get(config_key, '')
            return api_key if api_key else None
        return None
    
    def set_api_key(self, service: str, api_key: str):
        """Set API key for a specific service"""
        key_map = {
            'ipinfo': 'ipinfo_api_key',
            'virustotal': 'virustotal_api_key',
            'abuseipdb': 'abuseipdb_api_key'
        }
        
        config_key = key_map.get(service.lower())
        if config_key:
            self.set(config_key, api_key)
    
    def get_cache_dir(self) -> Path:
        """Get cache directory path"""
        cache_dir = self.config_dir / 'cache'
        cache_dir.mkdir(exist_ok=True)
        return cache_dir
    
    def get_log_dir(self) -> Path:
        """Get log directory path"""
        log_dir = self.config_dir / 'logs'
        log_dir.mkdir(exist_ok=True)
        return log_dir
    
    def export_settings(self, file_path: str):
        """Export settings to a file"""
        try:
            with open(file_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error exporting settings: {e}")
            return False
    
    def import_settings(self, file_path: str):
        """Import settings from a file"""
        try:
            with open(file_path, 'r') as f:
                imported_config = json.load(f)
                # Validate and merge with defaults
                default_config = self._get_default_config()
                default_config.update(imported_config)
                self.config = default_config
                self.save_config()
            return True
        except Exception as e:
            print(f"Error importing settings: {e}")
            return False

class ThemeManager:
    """Manages application themes and styles"""
    
    THEMES = {
        'dark': {
            'window_bg': '#1e1e1e',
            'widget_bg': '#2d2d2d',
            'text_color': '#ffffff',
            'text_secondary': '#b0b0b0',
            'accent_color': '#ff9800',
            'success_color': '#4caf50',
            'error_color': '#f44336',
            'warning_color': '#ff9800',
            'border_color': '#404040',
            'hover_bg': '#3a3a3a',
            'selected_bg': '#404040'
        },
        'light': {
            'window_bg': '#f7f5f3',
            'widget_bg': '#faf8f6',
            'text_color': '#2d2d2d',
            'text_secondary': '#6b6b6b',
            'accent_color': '#d97706',
            'success_color': '#16a34a',
            'error_color': '#dc2626',
            'warning_color': '#d97706',
            'border_color': '#e5e1dd',
            'hover_bg': '#f1ede8',
            'selected_bg': '#e8dcc6'
        },
        'blue': {
            'window_bg': '#0d1117',
            'widget_bg': '#161b22',
            'text_color': '#c9d1d9',
            'text_secondary': '#8b949e',
            'accent_color': '#58a6ff',
            'success_color': '#56d364',
            'error_color': '#f85149',
            'warning_color': '#d29922',
            'border_color': '#30363d',
            'hover_bg': '#1f2428',
            'selected_bg': '#1f6feb'
        }
    }
    
    @classmethod
    def get_theme(cls, theme_name: str) -> Dict[str, str]:
        """Get theme configuration"""
        return cls.THEMES.get(theme_name, cls.THEMES['dark'])
    
    @classmethod
    def get_stylesheet(cls, theme_name: str) -> str:
        """Generate Qt stylesheet from theme"""
        theme = cls.get_theme(theme_name)
        
        stylesheet = f"""
        QMainWindow {{
            background-color: {theme['window_bg']};
        }}
        
        QWidget {{
            background-color: {theme['widget_bg']};
            color: {theme['text_color']};
        }}
        
        QTextEdit, QLineEdit, QPlainTextEdit {{
            background-color: {theme['widget_bg']};
            color: {theme['text_color']};
            border: 1px solid {theme['border_color']};
            border-radius: 4px;
            padding: 4px;
        }}
        
        QPushButton {{
            background-color: {theme['widget_bg']};
            color: {theme['text_color']};
            border: 1px solid {theme['border_color']};
            border-radius: 4px;
            padding: 6px 12px;
        }}
        
        QPushButton:hover {{
            background-color: {theme['hover_bg']};
        }}
        
        QPushButton:pressed {{
            background-color: {theme['selected_bg']};
        }}
        
        QTableWidget {{
            background-color: {theme['widget_bg']};
            alternate-background-color: {theme['hover_bg']};
            gridline-color: {theme['border_color']};
        }}
        
        QHeaderView::section {{
            background-color: {theme['widget_bg']};
            color: {theme['text_color']};
            border: 1px solid {theme['border_color']};
            padding: 4px;
        }}
        
        QTreeWidget {{
            background-color: {theme['widget_bg']};
            alternate-background-color: {theme['hover_bg']};
        }}
        
        QTabWidget::pane {{
            background-color: {theme['widget_bg']};
            border: 1px solid {theme['border_color']};
        }}
        
        QTabBar::tab {{
            background-color: {theme['widget_bg']};
            color: {theme['text_color']};
            padding: 8px 16px;
            border: 1px solid {theme['border_color']};
        }}
        
        QTabBar::tab:selected {{
            background-color: {theme['selected_bg']};
        }}
        
        QGroupBox {{
            color: {theme['text_color']};
            border: 1px solid {theme['border_color']};
            border-radius: 4px;
            margin-top: 8px;
            padding-top: 8px;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }}
        
        QMenuBar {{
            background-color: {theme['widget_bg']};
            color: {theme['text_color']};
        }}
        
        QMenuBar::item:selected {{
            background-color: {theme['hover_bg']};
        }}
        
        QMenu {{
            background-color: {theme['widget_bg']};
            color: {theme['text_color']};
            border: 1px solid {theme['border_color']};
        }}
        
        QMenu::item:selected {{
            background-color: {theme['hover_bg']};
        }}
        
        QStatusBar {{
            background-color: {theme['widget_bg']};
            color: {theme['text_secondary']};
        }}
        
        QProgressBar {{
            background-color: {theme['widget_bg']};
            border: 1px solid {theme['border_color']};
            border-radius: 4px;
            text-align: center;
        }}
        
        QProgressBar::chunk {{
            background-color: {theme['accent_color']};
            border-radius: 3px;
        }}
        """
        
        return stylesheet