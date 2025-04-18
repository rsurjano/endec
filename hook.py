import os
import shutil
from dotenv import load_dotenv

def load_env():
    """Load environment variables from .env file."""
    env_file = ".env"
    if not os.path.exists(env_file):
        raise FileNotFoundError("Error: .env file not found. Please create one with the destination path.")
    load_dotenv(dotenv_path=env_file)

def get_paths():
    """Get the source and destination paths."""
    # Source is relative to the script's execution directory
    source = os.path.join(os.getcwd(), "vault")

    # Load destination folder from .env
    destination = os.getenv("DESTINATION_FOLDER")
    if not destination:
        raise ValueError("Error: DESTINATION_FOLDER is not set in the .env file.")

    # Ensure compatibility with the current operating system
    destination = os.path.expanduser(destination)  # Expand ~ to the user's home directory
    destination = os.path.normpath(destination)    # Normalize the path for the current OS

    return source, destination

def copy_files(source_dir, destination_dir):
    """Copy files from source to destination, skipping existing files."""
    if not os.path.exists(source_dir):
        print(f"Error: Source directory '{source_dir}' does not exist.")
        return

    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir)  # Create destination directory if it doesn't exist

    for root, dirs, files in os.walk(source_dir):
        # Calculate the relative path from the source directory
        relative_path = os.path.relpath(root, source_dir)
        target_dir = os.path.join(destination_dir, relative_path)

        # Create target directory if it doesn't exist
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        for file in files:
            source_file = os.path.join(root, file)
            target_file = os.path.join(target_dir, file)

            # Skip the file if it already exists in the destination
            if not os.path.exists(target_file):
                shutil.copy2(source_file, target_file)  # Copy file with metadata
                print(f"Copied: {source_file} -> {target_file}")
            else:
                print(f"Skipped (already exists): {target_file}")

def main():
    """Main function to execute the script."""
    try:
        load_env()
        source, destination = get_paths()
        print(f"Source: {source}")
        print(f"Destination: {destination}")
        copy_files(source, destination)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
