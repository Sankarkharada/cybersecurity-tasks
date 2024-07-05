from PIL import Image
import os

def encrypt_image(image_path, output_path, key):
    with Image.open(image_path) as img:
        encrypted_img = img.copy()
        pixels = encrypted_img.load()

        for i in range(encrypted_img.width):
            for j in range(encrypted_img.height):
                r, g, b = pixels[i, j]

                # Encrypt each pixel by adding the key value and taking modulo 256
                r = (r + key) % 256
                g = (g + key) % 256
                b = (b + key) % 256

                pixels[i, j] = (r, g, b)
        
        encrypted_img.save(output_path)
        print(f"Encrypted image saved to {output_path}")

def decrypt_image(image_path, output_path, key):
    with Image.open(image_path) as img:
        decrypted_img = img.copy()
        pixels = decrypted_img.load()

        for i in range(decrypted_img.width):
            for j in range(decrypted_img.height):
                r, g, b = pixels[i, j]

                # Decrypt each pixel by subtracting the key value and taking modulo 256
                r = (r - key) % 256
                g = (g - key) % 256
                b = (b - key) % 256

                pixels[i, j] = (r, g, b)
        
        decrypted_img.save(output_path)
        print(f"Decrypted image saved to {output_path}")

def main():
    while True:
        choice = input("Would you like to encrypt or decrypt an image? (enter 'encrypt' or 'decrypt', or 'exit' to quit): ").lower()
        if choice == 'exit':
            break
        image_path = input("Enter the path of the image: ")
        output_path = input("Enter the path to save the output image: ")
        key = int(input("Enter the encryption/decryption key (integer): "))

        if choice == 'encrypt':
            encrypt_image(image_path, output_path, key)
        elif choice == 'decrypt':
            decrypt_image(image_path, output_path, key)
        else:
            print("Invalid choice. Please enter 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
