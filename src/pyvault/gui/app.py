"""
PyVault GUI Application

Entry point for the graphical user interface.
"""

import sys
import os
from typing import Optional

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from .main_window import MainWindow
from .dialogs.password_dialog import PasswordDialog
from .styles.theme import Theme, get_stylesheet


def verify_password(password: str) -> bool:
    """
    Verify the password against the vault.
    
    Args:
        password: Password to verify
        
    Returns:
        True if password is valid
    """
    from ..vault import get_fernet, get_config, get_files
    from ..crypto import hash_salt
    
    try:
        config = get_config()
        fernet = get_fernet(password)
        salt = bytes.fromhex(config["salt"])
        salt_hash = hash_salt(salt)
        
        # Try to decrypt at least one file to verify password
        vault_files = get_files()
        
        if not vault_files['encrypted_files']:
            # No files to verify, assume password is correct
            return True
        
        # Try the first file
        test_file = list(vault_files['encrypted_files'])[0]
        
        from ..container import ContainerReader
        from ..settings import FILENAME_DECRYPT_CHUNK_SIZE
        
        with open(test_file, 'rb') as f:
            reader = ContainerReader(f)
            is_new = reader.detect_format()
            
            if is_new:
                reader.read_header()
                file_salt = reader.read_salt()
                
                if file_salt != salt_hash:
                    return False
                
                encrypted_name = reader.read_encrypted_filename(FILENAME_DECRYPT_CHUNK_SIZE)
            else:
                file_salt = f.read(32)
                
                if file_salt != salt_hash:
                    return False
                
                encrypted_name = f.read(FILENAME_DECRYPT_CHUNK_SIZE)
            
            # Try to decrypt filename
            fernet.decrypt(encrypted_name)
            return True
            
    except Exception:
        return False


def run_gui() -> int:
    """
    Run the PyVault GUI application.
    
    Returns:
        Exit code (0 for success)
    """
    # Check if vault is initialized
    if not os.path.exists("config.json"):
        print("Error: Vault not initialized. Please run 'vault init' first.")
        return 1
    
    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("PyVault")
    app.setStyle("Fusion")  # Consistent cross-platform style
    
    # Set default font
    font = QFont(Theme.typography.font_family)
    font.setPixelSize(Theme.typography.size_md)
    app.setFont(font)
    
    # Apply global stylesheet
    app.setStyleSheet(get_stylesheet())
    
    # Show password dialog
    password_dialog = PasswordDialog()
    password: Optional[str] = None
    
    def on_password_entered(pwd: str):
        nonlocal password
        
        # Verify password
        if verify_password(pwd):
            password = pwd
            password_dialog.accept()
        else:
            password_dialog.show_error("Invalid password. Please try again.")
    
    password_dialog.password_entered.connect(on_password_entered)
    
    result = password_dialog.exec()
    
    if result != PasswordDialog.DialogCode.Accepted or password is None:
        return 0  # User cancelled
    
    # Create and show main window
    main_window = MainWindow(password)
    main_window.show()
    
    # Run event loop
    return app.exec()


def main():
    """Main entry point."""
    sys.exit(run_gui())


if __name__ == "__main__":
    main()

