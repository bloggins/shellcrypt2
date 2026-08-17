python3 shellcrypt.py -i sc.bin -m aes -k 0123456789abcdef0123456789abcdef --encode base64 -f c

python3 shellcrypt.py -i sc.bin -m rc4 -k 's3cr3t' --stub rc4 -o pic.bin --verify --meta loader.json

python3 shellcrypt.py -i sc.bin -m uuid -f txt
