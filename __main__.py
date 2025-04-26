"""
This file is part of the Endec project developed by Arnat Technologies.

Endec is a developer-friendly encryption toolkit combining AES-256 and RSA-4096
to securely compress, encrypt, and decrypt sensitive data. It includes RSA key
generation, checksum verification, and encrypted backups with a unified CLI for
seamless integration into workflows.

Endec is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

Endec is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Endec.
If not, see <https://www.gnu.org/licenses/>.

Copyright (C) 2025 Arnat Technologies
"""
import os
import subprocess
import sys
import argparse

def run_script(script_name, *args):
    """Run a Python script with the provided arguments."""
    try:
        # Check if debugging is enabled
        if os.getenv("DEBUG_MODE") == "1":
            # Import the script as a module and run its main function
            if script_name == "encrypt.py":
                import encrypt
                encrypt.main()
            elif script_name == "decrypt.py":
                import decrypt
                decrypt.main()
            elif script_name == "generate.py":
                import generate
                generate.main()
            return

        # Otherwise, run as a subprocess
        pull_latest_changes()
        command = [sys.executable, script_name] + list(args)
        result = subprocess.run(command, check=False)  # Allow non-zero exit codes
        print(f"Executed: {script_name}")

        # Handle return codes for all scripts
        if result.returncode == 0:
            print(f"Script '{script_name}' executed successfully.")
            if script_name == "encrypt.py":
                run_hook()  # Only run the hook for encrypt.py if it succeeds
        elif result.returncode == 1:
            print(f"Script '{script_name}' exited with code 1: No changes detected or user aborted.")
        elif result.returncode == 2:
            print(f"Script '{script_name}' exited with code 2: Invalid input or configuration error.")
        else:
            print(f"Script '{script_name}' exited with code {result.returncode}: An unexpected error occurred.")

    except subprocess.CalledProcessError as e:
        print(f"Error: Script '{script_name}' failed with exit code {e.returncode}.")
    except Exception as e:
        print(f"An unexpected error occurred while running '{script_name}': {e}")

def check_staged_changes():
    """Check if there are staged changes in the Git repository."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        staged_files = result.stdout.strip()
        if staged_files:
            print("Error: There are staged changes in the repository. Please commit or unstage them before proceeding.")
            print("Staged changes:")
            print(staged_files)
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to check for staged changes. Exit code: {e.returncode}.")
        sys.exit(1)

def pull_latest_changes():
    """Pull the latest changes from the remote repository."""
    try:
        print("Pulling latest changes from the remote repository...")
        subprocess.run(["git", "pull", "--rebase"], check=True)
        print("Successfully pulled the latest changes.")
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to pull the latest changes. Exit code: {e.returncode}.")
        sys.exit(1)

def run_hook():
    """Run hook.py if it exists."""
    hook_script = "hook.py"
    if os.path.exists(hook_script):
        print(f"{hook_script} found. Executing {hook_script}...")
        try:
            subprocess.run([sys.executable, hook_script], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: {hook_script} failed with exit code {e.returncode}.")
    else:
        print(f"{hook_script} not found. Skipping.")

def get_command_from_input():
    """Prompt the user to select a command interactively."""
    options = {
        "1": "encrypt",
        "2": "decrypt",
        "3": "generate",
        "encrypt": "encrypt",
        "decrypt": "decrypt",
        "generate": "generate"
    }
    print("Please select an option:")
    for key, value in {"1": "Encrypt", "2": "Decrypt", "3": "Generate"}.items():
        print(f"{key}. {value}")
    print("Or type the command directly (encrypt, decrypt, generate).")

    choice = input("Enter your choice: ").strip().lower()
    return options.get(choice)

def main():
    """Main entry point for the CLI."""
    # Check for staged changes
    check_staged_changes()

    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="CLI for encryption, decryption, and RSA key generation."
    )
    parser.add_argument(
        "command",
        nargs="?",
        help="Command to run (encrypt, decrypt, generate, or 1/2/3)."
    )
    args = parser.parse_args()

    # Map numeric inputs to commands
    command_map = {
        "1": "encrypt",
        "2": "decrypt",
        "3": "generate"
    }

    # Determine the command
    command = args.command or get_command_from_input()
    command = command_map.get(command, command)  # Map numeric input to command

    if command in {"encrypt", "decrypt", "generate"}:
        run_script(f"{command}.py")
    else:
        print("Invalid command. Use 'encrypt', 'decrypt', 'generate', or 1/2/3.")
        sys.exit(1)

if __name__ == "__main__":
    main()
