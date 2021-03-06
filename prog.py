import random
import string
import typer
import base64
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


app = typer.Typer()


def generatePassword():
    break_aparts = 3
    separators = ['-', '_']
    result = ''

    for iteration in range(break_aparts):
        length = random.randrange(4, 8)
        separator = random.choice(separators)

        for _ in range(length):
            isLetters = bool(random.getrandbits(1))
            if isLetters:
                result += random.choice(string.ascii_letters)
            else:
                result += random.choice(string.digits)

        if iteration < break_aparts-1:
            result += separator

    return result


def deriveKey(user_password):
    if user_password:
        password_bytes = bytes(user_password, 'utf-8')
        password_hash = hashlib.sha256(password_bytes).digest()
        salt = password_hash

        # derive
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,)
        key = base64.urlsafe_b64encode(kdf.derive(user_password.encode()))

        return key


@app.command()
def encrypt(file: str):
    # Get data
    path = Path(file)
    if path.is_file():
        with open(path, 'rb') as file:
            original = file.read()
            file.close()
    else:
        typer.echo('Failed to open file')
        return

    # Ask user for the key
    password = typer.prompt('Enter a password (enter \'skip\' to generate random)')
    if password.lower() == 'skip':
        typer.echo('Generating random password...')
        password = generatePassword()
        typer.echo(f'Generated: {password}')
    else:
        typer.echo(f'You entered: {password}')
    
    # Derive key
    key = deriveKey(password)

    # Generate Fernet from key
    fernet = Fernet(key)
    
    try:
        # Encrypt Data
        encrypted = fernet.encrypt(original)

        # Write encrypted data
        # TODO: change file extension to something approperiate
        with open (path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
            encrypted_file.close()
    except:
        typer.echo('Something went wrong...')

    typer.echo('File was encrypted successfully!')


@app.command()
def decrypt(file: str):
    # Get data
    path = Path(file)
    if path.is_file():
        with open(path, 'rb') as file:
            encrypted = file.read()
            file.close()
    else:
        typer.echo('Failed to open file')
        return

    # Ask user for the key
    password = typer.prompt('Enter a password')
    
    # Derive key
    key = deriveKey(password)

    # Generate Fernet from key
    fernet = Fernet(key)
        
    try:
        # Encrypt Data
        decrypted = fernet.decrypt(encrypted)

        # Write decrypted data
        with open(path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
            decrypted_file.close()
    except:
        typer.echo('Wrong password...')
        return

    typer.echo('File was decrypted successfully!')


if __name__ == "__main__":
    app()
