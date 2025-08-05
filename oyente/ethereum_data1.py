# this the interface to create your own data source
# this class pings a private / public blockchain to get the balance and code information

from typing import Any

from web3 import Web3


class EthereumData:
    def __init__(self) -> None:
        self.host = "x.x.x.x"
        self.port = "8545"
        # Updated to use HTTPProvider instead of deprecated KeepAliveRPCProvider
        self.web3 = Web3(Web3.HTTPProvider(f"http://{self.host}:{self.port}"))

    def getBalance(self, address: str) -> Any:  # noqa: N802
        # Convert to checksum address before calling web3
        checksum_address = self.web3.toChecksumAddress(address)  # type: ignore[attr-defined]
        return self.web3.eth.get_balance(checksum_address)

    def getCode(self, address: str) -> Any:  # noqa: N802
        # Convert to checksum address before calling web3
        checksum_address = self.web3.toChecksumAddress(address)  # type: ignore[attr-defined]
        return self.web3.eth.get_code(checksum_address)
