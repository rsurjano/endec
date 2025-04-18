import argparse
import subprocess
import sys

def run_script(script_name, *args):
    """Run a Python script with the provided arguments."""
    try:
        command = [sys.executable, script_name] + list(args)
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Script '{script_name}' failed with exit code {e.returncode}.")
    except Exception as e:
        print(f"An unexpected error occurred while running '{script_name}': {e}")

def prompt_selection():
    """Prompt the user to select an option interactively."""
    options = {
        "1": "encrypt",
        "2": "decrypt",
        "3": "generate",
        "encrypt": "encrypt",
        "decrypt": "decrypt",
        "generate": "generate"
    }
    print("Please select an option:")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Generate")
    print("Or type the command directly (encrypt, decrypt, generate).")

    choice = input("Enter your choice: ").strip().lower()
    return options.get(choice)

def main():
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
    command = args.command
    if not command:
        # If no command is provided, prompt the user for a selection
        command = prompt_selection()
        if not command:
            print("Invalid selection. Exiting.")
            sys.exit(1)
    else:
        # Map numeric input to the corresponding command
        command = command_map.get(command, command)

    # Run the appropriate script
    if command == "encrypt":
        run_script("encrypt.py")
    elif command == "decrypt":
        run_script("decrypt.py")
    elif command == "generate":
        run_script("generate.py")
    else:
        print("Invalid command. Use 'encrypt', 'decrypt', 'generate', or 1/2/3.")
        sys.exit(1)

if __name__ == "__main__":
    main()
