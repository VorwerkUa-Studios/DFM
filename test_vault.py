from tools.vault.offset_vault import add_offset, list_offsets

r1 = add_offset('stalker2','PlayerHealth',
    address_hex='0x14A2B3C00',
    aob_pattern='48 8B 05 ?? ?? ?? ?? 48 85 C0 74',
    module='Stalker2-Win64-Shipping.exe',
    notes='Health component pointer')

r2 = add_offset('stalker2','TakeDamage',
    address_hex='0x14B1234AB',
    aob_pattern='40 55 53 56 57 41 54 41 56 48 8D',
    module='Stalker2-Win64-Shipping.exe')

r3 = add_offset('minecraft','BlockBreak',
    aob_pattern='55 8B EC 83 EC ?? 56 8B 75 08',
    module='minecraft.jar')

print("add r1:", r1)
print("add r2:", r2)
print("add r3:", r3)

lst = list_offsets()
print("Vault entries:", lst['count'])
for o in lst['offsets']:
    game = o["game"]
    name = o["name"]
    addr = o["address_hex"]
    print(f"  [{game}] {name} @ {addr}")
