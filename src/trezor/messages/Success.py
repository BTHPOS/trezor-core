# Automatically generated by pb2py
# fmt: off
import protobuf as p


class Success(p.MessageType):
    MESSAGE_WIRE_TYPE = 2

    def __init__(
        self,
        message: str = None,
    ) -> None:
        self.message = message

    @classmethod
    def get_fields(cls):
        return {
            1: ('message', p.UnicodeType, 0),
        }
