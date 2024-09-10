from PIL import Image
from io import BytesIO
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Function to convert image to byte array
def image_to_byte_array(image_path):
    with Image.open(image_path) as img:
        img_byte_array = BytesIO()
        img.save(img_byte_array, format=img.format)
        return img_byte_array.getvalue()

# Function to encrypt byte array using AES
def encrypt_image(image_bytes, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(image_bytes)
    return cipher.nonce, ciphertext, tag

# Function to decrypt byte array using AES
def decrypt_image(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data

# Paths to the image
image_path = r'C:\Users\91620\Desktop\aes\sin.jpg'
encrypted_image_path = r'C:\Users\91620\Desktop\aes\encrypted_image.bin'
decrypted_image_path = r'C:\Users\91620\Desktop\aes\decrypted_image.jpg'

# Convert image to byte array
image_bytes = image_to_byte_array(image_path)

# Generate AES key
key = get_random_bytes(16)  # AES-128 key

# Encrypt image byte array
nonce, ciphertext, tag = encrypt_image(image_bytes, key)

# Save encrypted data to a file
with open(encrypted_image_path, 'wb') as file:
    file.write(nonce + tag + ciphertext)

# Read encrypted data from file
with open(encrypted_image_path, 'rb') as file:
    nonce = file.read(16)
    tag = file.read(16)
    ciphertext = file.read()

# Decrypt image byte array
decrypted_bytes = decrypt_image(nonce, ciphertext, tag, key)

# Save decrypted byte array as an image
decrypted_image = Image.open(BytesIO(decrypted_bytes))
decrypted_image.save(decrypted_image_path)

print("Encryption and decryption completed successfully.")
