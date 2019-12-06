import sys
import json

def to_hex(d):
    return hex(int(d)).rstrip('L')
    return d

class vk_ethsnarks(object):
    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

if len(sys.argv) != 3:
    print("Usage: ")
    print("<input_vk.json> <ethsnarks_vk.json>")

f = json.load(open(sys.argv[1]))

vk = vk_ethsnarks()
# alpha
vk.alpha = []
for i in range(2):
    vk.alpha.append(to_hex(f["vk_alfa_1"][i]))
# beta
vk.beta = [[], []]
for i in range(2):
    for j in range(2):
        vk.beta[i].append(to_hex(f["vk_beta_2"][i][1-j]))
# gamma
vk.gamma = [[], []]
for i in range(2):
    for j in range(2):
        vk.gamma[i].append(to_hex(f["vk_gamma_2"][i][1-j]))
# delta
vk.delta = [[], []]
for i in range(2):
    for j in range(2):
        vk.delta[i].append(to_hex(f["vk_delta_2"][i][1-j]))
# gammaABC
vk.gammaABC = [[], []]
for i in range(2):
    for j in range(2):
        vk.gammaABC[i].append(to_hex(f["IC"][i][j]))

f3 = open(sys.argv[2], 'w')
f3.write(vk.to_json())
f3.close()

print("vk file created: " + str(sys.argv[2]))
