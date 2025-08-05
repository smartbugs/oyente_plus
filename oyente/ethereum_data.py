# this the interface to create your own data source
# this class pings etherscan to get the latest code and balance information

import logging

import requests


log = logging.getLogger(__name__)


class EthereumData:
    def __init__(self, contract_address):
        self.apiDomain = "https://api.etherscan.io/api"
        self.apikey = "VT4IW6VK7VES1Q9NYFI74YKH8U7QW9XRHN"
        self.contract_addr = contract_address

    def getBalance(self, address):  # noqa: N802
        try:
            api_endpoint = (
                f"{self.apiDomain}?module=account&action=balance&address={address}&tag=latest&apikey={self.apikey}"
            )
            r = requests.get(api_endpoint, timeout=30)
            result = r.json()
            status = result["message"]
            if status == "OK":
                result = result["result"]
        except Exception as e:
            log.exception(f"Error at: contract address: {address}")
            raise e
        return result

    def getCode(self, address):  # noqa: N802
        try:
            api_endpoint = (
                f"{self.apiDomain}?module=proxy&action=eth_getCode&address={address}&tag=latest&apikey={self.apikey}"
            )
            r = requests.get(api_endpoint, timeout=30)
            result = r.json()["result"]
        except Exception as e:
            log.exception(f"Error at: contract address: {address}")
            raise e
        return result

    def getStorageAt(self, position):  # noqa: N802
        try:
            position = hex(position)
            if position[-1] == "L":
                position = position[:-1]
            api_endpoint = f"{self.apiDomain}?module=proxy&action=eth_getStorageAt&address={self.contract_addr}&position={position}&tag=latest&apikey={self.apikey}"
            r = requests.get(api_endpoint, timeout=30)
            result = r.json()["result"]
        except Exception as e:
            if str(e) != "timeout":
                log.exception(f"Error at: contract address: {self.contract_addr}, position: {position}")
            raise
        return int(result, 16)
