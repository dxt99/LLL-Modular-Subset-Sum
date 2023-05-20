from typing import List
from Cryptodome.Util.number import bytes_to_long, long_to_bytes
from merkle import Merkle
import time

class Attack:
    def __init__(self, pub_key: List[int], modulus: int):
        self.b = pub_key
        self.q = modulus
        self.M = []
        size = len(self.b) + 2
        for i in range(size):
            arr = [0 for _ in range(size)]
            if i == size - 1:
                arr = [1/2 for _ in range(size)]
            arr[i] = 1
            if i < len(self.b):
                arr[-1] = self.b[i]
            else:
                arr[-1] = self.q
            self.M.append(arr)
        self.M[-2][-2] = 0
        self.size = size
    
    def decrypt_one(self, ciphertext: bytes):
        self.M[-1][-1] = bytes_to_long(ciphertext)
        M = Matrix(QQ, self.size)
        for i in range(self.size):
            for j in range(self.size):
                M[i, j] = self.M[i][j]
        L = M.LLL()
        pt = ""
        if L[0, -1] == 0:
            for c in L[0][:-2]:
                if c > 0:
                    pt += "0"
                else:
                    pt += "1"
            pt = long_to_bytes(int(pt, 2))
        else:
            print("Fail")
            pt = b"-"
        return pt
    
    def decrypt(self, ciphertext: List[bytes]):
        plain = b""
        for c in ciphertext:
            plain += self.decrypt_one(c)
        
        print(f"Derived Plaintext: {plain}")



def attack(plaintext):
    print("=============================")
    print(f"Original plaintext:{plaintext}")
    cipher = Merkle()
    ct = cipher.encrypt(plaintext)
    print("Attack starts")
    start = time.time()
    attack = Attack(cipher.b, cipher.q)
    attack.decrypt(ct)
    print("Attack done")
    print(f"Time elapsed: {(time.time()-start)*1000}ms")
    print("=============================")

plaintext = b'hello'
attack(plaintext)
plaintext = b'hello'
attack(plaintext)
plaintext = b'abcdef'
attack(plaintext)
plaintext = b'abcdef'*10
attack(plaintext)
plaintext = b'KessokuBand'*10
attack(plaintext)