import base64, hashlib, hmac, struct, sys, time
secret = base64.b32decode(sys.argv[1] + "=" * (-len(sys.argv[1]) % 8))
step = int(time.time()) // 30 + (int(sys.argv[2]) if len(sys.argv) > 2 else 0)
h = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
o = h[19] & 0xF
print(f"{(struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000:06}")
