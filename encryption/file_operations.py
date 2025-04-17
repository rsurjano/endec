import shutil
import subprocess


def compress_folder(folder_path, output_path, compression='zip'):
    if compression == 'store':
        shutil.make_archive(output_path, 'zip', folder_path)
    else:
        shutil.make_archive(output_path, compression, folder_path)


def decompress_folder(zip_path, extract_path):
    shutil.unpack_archive(zip_path, extract_path, 'zip')


def git_commit(file_path, date_str):
    subprocess.run(['git', 'add', file_path])
    commit_message = f"Add encrypted data backup {date_str}"
    subprocess.run(['git', 'commit', '-m', commit_message])
