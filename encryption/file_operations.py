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
