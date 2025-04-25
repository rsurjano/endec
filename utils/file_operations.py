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
import shutil
import zipfile
import subprocess


def compress_folder(folder_path, output_path, compression='zip'):
    if compression == 'store':
        shutil.make_archive(output_path, 'zip', folder_path)
    else:
        shutil.make_archive(output_path, compression, folder_path)


def decompress_folder(zip_path, extract_path, password=None):
    """Decompress a .zip file, optionally using a password."""
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        if password:
            zip_ref.setpassword(password.encode())
        zip_ref.extractall(extract_path)


def git_commit(file_path, date_str):
    subprocess.run(['git', 'add', file_path])
    commit_message = f"Add encrypted data backup {date_str}"
    subprocess.run(['git', 'commit', '-m', commit_message])
