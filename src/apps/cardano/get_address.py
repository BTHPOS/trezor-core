from trezor import log, ui, wire
from trezor.messages.CardanoAddress import CardanoAddress

from apps.cardano import seed
from apps.cardano.address import derive_address_and_node
from apps.cardano.layout import confirm_with_pagination


async def get_address(ctx, msg):
    keychain = await seed.get_keychain(ctx)

    try:
        address, _ = derive_address_and_node(keychain, msg.address_n)
    except ValueError as e:
        if __debug__:
            log.exception(__name__, e)
        raise wire.ProcessError("Deriving address failed")

    if msg.show_display:
        if not await confirm_with_pagination(
            ctx, address, "Export address", icon=ui.ICON_SEND, icon_color=ui.GREEN
        ):
            raise wire.ActionCancelled("Exporting cancelled")

    return CardanoAddress(address=address)
