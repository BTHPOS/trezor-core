from trezor import wire
from trezor.crypto import bip32, bip39

from apps.common import cache, storage
from apps.common.request_passphrase import protect_by_passphrase


class Keychain:
    def __init__(self, roots, namespaces):
        self.roots = roots
        self.namespaces = namespaces

    def derive(self, node_path: list, curve_name: str = "secp256k1") -> bip32.HDNode:
        root_index = 0
        for curve, *path in self.namespaces:
            prefix = node_path[: len(path)]
            suffix = node_path[len(path) :]
            if curve == curve_name and path == prefix:
                break
            root_index += 1
        else:
            raise wire.DataError("Forbidden key path")
        node = self.roots[root_index].clone()
        node.derive_path(suffix)
        return node


async def get_keychain(ctx: wire.Context, namespaces: list = None) -> Keychain:
    if not storage.is_initialized():
        raise wire.ProcessError("Device is not initialized")
    seed = cache.get_seed()
    if seed is None:
        passphrase = cache.get_passphrase()
        if passphrase is None:
            passphrase = await protect_by_passphrase(ctx)
            cache.set_passphrase(passphrase)
        seed = bip39.seed(storage.get_mnemonic(), passphrase)
        cache.set_seed(seed)
    if namespaces is None:
        # allow the whole keyspace by default
        namespaces = [
            ["curve25519"],
            ["ed25519"],
            ["ed25519-keccak"],
            ["nist256p1"],
            ["secp256k1"],
            ["secp256k1-decred"],
            ["secp256k1-groestl"],
            ["secp256k1-smart"],
        ]
    roots = [_derive_node(seed, curve_name, path) for curve_name, *path in namespaces]
    keychain = Keychain(roots, namespaces)
    return keychain


def _derive_node(seed: bytes, curve_name: str, path: list) -> bip32.HDNode:
    node = bip32.from_seed(seed, curve_name)
    node.derive_path(path)
    return node


def derive_node_without_passphrase(
    path: list, curve_name: str = "secp256k1"
) -> bip32.HDNode:
    if not storage.is_initialized():
        raise Exception("Device is not initialized")
    seed = bip39.seed(storage.get_mnemonic(), "")
    node = bip32.from_seed(seed, curve_name)
    node.derive_path(path)
    return node


def remove_ed25519_prefix(pubkey: bytes) -> bytes:
    # 0x01 prefix is not part of the actual public key, hence removed
    return pubkey[1:]
