import os
import subprocess
import sys
import argparse

def run_script(script_name, *args):
    """Run a Python script with the provided arguments."""
    try:
        command = [sys.executable, script_name] + list(args)
        subprocess.run(command, check=True)
        print(f"Executed: {script_name}")

        # Run hook.py if encrypt.py is executed
        if script_name == "encrypt.py":
            run_hook()

    except subprocess.CalledProcessError as e:
        print(f"Error: Script '{script_name}' failed with exit code {e.returncode}.")
    except Exception as e:
        print(f"An unexpected error occurred while running '{script_name}': {e}")

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
