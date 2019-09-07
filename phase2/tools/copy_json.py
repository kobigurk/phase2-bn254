import json

f = json.load(open('proving_key.json'))
f2 = json.load(open('pk.json'))

for k in f2:
  f[k] = f2[k]

f3 = open('transformed_pk.json', 'w')
f3.write(json.dumps(f))
f3.close()

f = json.load(open('verification_key.json'))
f2 = json.load(open('vk.json'))

for k in f2:
  f[k] = f2[k]

del f['vk_alfabeta_12']

f3 = open('transformed_vk.json', 'w')
f3.write(json.dumps(f))
f3.close()
