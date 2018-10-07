from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import os
import shutil
if os.name == 'nt':
    import string
    from ctypes import windll
backend = default_backend()

def clearscreen():
    if os.name == 'nt':
        os.system("cls")
    else:
        os.system("clear")


def GetAllFiles(root, excludeencryptedfile=True, onlygetencryptedfiles=False):
	if onlygetencryptedfiles == True:
		filelist = [os.path.join(r,file) for r,d,f in os.walk(root) for file in f]
		for i in filelist:
			if ".pngu" not in i:
				filelist.remove(i)
		return filelist
	elif excludeencryptedfile == True:
		filelist = [os.path.join(r,file) for r,d,f in os.walk(root) for file in f]
		for i in filelist:
			if ".pngu" in i:
				filelist.remove(i)
		return filelist
	elif excludeencryptedfile == False:
		return [os.path.join(r,file) for r,d,f in os.walk(root) for file in f]
	
def get_used_space(partition):
    return shutil.disk_usage(partition + ":/")[1]

def get_driveswin():
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drives.append(letter)
        bitmask >>= 1
    return drives

def encrypt(root): #Encrypt Function
	files = GetAllFiles(root)
	key = hashlib.md5(input("Key> ").encode()).hexdigest()
	perms = 0
	e = 0
	clearscreen()
	for num, i in enumerate(files):
		try:
			clearscreen()
			print("Status: " + str(round((num / len(files))* 100, 2)) + "%")
			IV = os.urandom(16)
			cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(IV), backend=backend)
			padder = padding.PKCS7(128).padder()
			encryptor = cipher.encryptor()
			file = open(i, "rb")
			raw = file.read()
			file.close()
			pad = padder.update(raw) + padder.finalize()
			enc = encryptor.update(pad) + encryptor.finalize()
			file = open(i, 'wb')
			file.write(IV+enc)
			file.close()
			os.rename(i, i + '.pngu')
		except PermissionError:
			perms = perms+1
			clearscreen()
			print("Status: " + str(round((num / len(files))* 100, 2)) + "%")
		except:
			print("Unable to encrypt " + i)
			e = e+1
			clearscreen()
			print("Status: " + str(round((num / len(files))* 100, 2)) + "%")
	print("Successfully encrypted "+str(len(files))+" file(s).")
	print("With " + str(perms) + " errors related to permissions. \n Try runnning as admin to solve this.")
	print("And " + str(e) + " unknown errors")

def decrypt(root):
	files = GetAllFiles(root, onlygetencryptedfiles=True)
	key = hashlib.md5(input("Key> ").encode()).hexdigest()
	e = 0
	for num, i in enumerate(files):
		try:
			clearscreen()
			print("Status: " + str(round((num / len(files))* 100, 2)) + "%")
			file = open(i, 'rb')
			IV = file.read(16)
			raw = file.read()
			file.close()
			cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(IV), backend=backend)
			decryptor = cipher.decryptor()
			dec = decryptor.update(raw) + decryptor.finalize()
			unpadder = padding.PKCS7(128).unpadder()
			unpad = unpadder.update(dec) + unpadder.finalize()
			file = open(i, 'wb')
			file.write(unpad)
			file.close()
			os.rename(i, os.path.splitext(i)[0])
			
		except:
			print("Unable to encrypt " + i)
			e = e+1
			clearscreen()
			print("Status: " + str(round((num / len(files))* 100, 2)) + "%")
	print("Successfully decrypted "+str(len(files))+" file(s).")
	print("And " + str(e) + " unknown errors")

def main():
	drivelist = get_driveswin()
	for i in range(0, len(drivelist)):
		used_space = round(get_used_space(drivelist[i]) / 1024 / 1024 / 1024, 3)
		print(str(i) + ". [" + drivelist[i]  + ":/ ]" + " Disk Usage = " + str(used_space) + " GB")
	root = input("Root> ")
	if int(root) > len(drivelist) - 1:
		print("Invalid number Try Again")
		main()
	root = drivelist[int(root)]
	mode = input("(E)ncrypt/(D)ecrypt\nMode> ").lower()
	if mode.startswith("E") or mode.startswith("e"):
		encrypt(root + ":\\")
	elif mode.startswith("D") or mode.startswith("d"):
		decrypt(root + ":\\")
	else:
		print("Invalid mode.. Try again")

	

if __name__ == "__main__":
	main()
