from Cryptodome.Util.number import getPrime, getRandomInteger, long_to_bytes, bytes_to_long
from typing import List

class Merkle:
    def __init__(self, n: int = 8):
        self.q = getPrime(128)
        self.n = n
        self.w = []
        for i in range(self.n):
            while True:
                cur = getRandomInteger(i+20)
                if cur > sum(self.w):
                    self.w.append(cur)
                    break
        self.r = getRandomInteger(127)
        self.b = [i * self.r for i in self.w]
    
    def encrypt(self, message: bytes) -> List[bytes]:
        ciphertext = []
        for byte in message:
            sum = 0
            s = format(byte, '#010b')[2:]
            assert(len(s)==len(self.b))
            for m, w in zip(s, self.b):
                if m=='1':
                    sum += w
            sum = sum % self.q
            ciphertext.append(long_to_bytes(sum))
        return ciphertext

    def decrypt(self, ciphertext: List[bytes])-> bytes:
        pt = b''
        for byte in ciphertext:
            binary = ""
            sum = bytes_to_long(byte) * pow(self.r, -1, self.q)
            sum %= self.q
            for w in reversed(self.w):
                if sum >= w:
                    sum -= w
                    binary = "1" + binary
                else:
                    binary = "0" + binary
            pt += long_to_bytes(int(binary, 2))
        return pt
    
    
if __name__ == '__main__':
    cipher = Merkle()
    ct = cipher.encrypt(b'hello')
    pt = cipher.decrypt(ct)
    print(ct, pt)