from web3.middleware import geth_poa_middleware
from ccxt.base.errors import ExchangeError
import time, random, requests, json
from termcolor import cprint
from loguru import logger
from sys import stderr
from settings import *
from tqdm import tqdm
from web3 import Web3
import hmac, base64
import telebot
import ctypes
import ccxt
import os


logger.remove()
logger.add(stderr, format="<white>{time:HH:mm:ss:SSS}</white> | <level>{level: <8}</level> | <level>{message}</level>")

ABRACADABRA_ABI = '[{"inputs":[{"internalType":"address","name":"_token","type":"address"},{"internalType":"contract IMintableBurnable","name":"_minterBurner","type":"address"},{"internalType":"uint8","name":"_sharedDecimals","type":"uint8"},{"internalType":"address","name":"_lzEndpoint","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint16","name":"_srcChainId","type":"uint16"},{"indexed":false,"internalType":"bytes","name":"_srcAddress","type":"bytes"},{"indexed":false,"internalType":"uint64","name":"_nonce","type":"uint64"},{"indexed":false,"internalType":"bytes32","name":"_hash","type":"bytes32"}],"name":"CallOFTReceivedSuccess","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint16","name":"_srcChainId","type":"uint16"},{"indexed":false,"internalType":"bytes","name":"_srcAddress","type":"bytes"},{"indexed":false,"internalType":"uint64","name":"_nonce","type":"uint64"},{"indexed":false,"internalType":"bytes","name":"_payload","type":"bytes"},{"indexed":false,"internalType":"bytes","name":"_reason","type":"bytes"}],"name":"MessageFailed","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"_address","type":"address"}],"name":"NonContractAddress","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint16","name":"_srcChainId","type":"uint16"},{"indexed":true,"internalType":"address","name":"_to","type":"address"},{"indexed":false,"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"ReceiveFromChain","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint16","name":"_srcChainId","type":"uint16"},{"indexed":false,"internalType":"bytes","name":"_srcAddress","type":"bytes"},{"indexed":false,"internalType":"uint64","name":"_nonce","type":"uint64"},{"indexed":false,"internalType":"bytes32","name":"_payloadHash","type":"bytes32"}],"name":"RetryMessageSuccess","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint16","name":"_dstChainId","type":"uint16"},{"indexed":true,"internalType":"address","name":"_from","type":"address"},{"indexed":true,"internalType":"bytes32","name":"_toAddress","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"SendToChain","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint16","name":"_dstChainId","type":"uint16"},{"indexed":false,"internalType":"uint16","name":"_type","type":"uint16"},{"indexed":false,"internalType":"uint256","name":"_minDstGas","type":"uint256"}],"name":"SetMinDstGas","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"precrime","type":"address"}],"name":"SetPrecrime","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint16","name":"_remoteChainId","type":"uint16"},{"indexed":false,"internalType":"bytes","name":"_path","type":"bytes"}],"name":"SetTrustedRemote","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint16","name":"_remoteChainId","type":"uint16"},{"indexed":false,"internalType":"bytes","name":"_remoteAddress","type":"bytes"}],"name":"SetTrustedRemoteAddress","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"bool","name":"_useCustomAdapterParams","type":"bool"}],"name":"SetUseCustomAdapterParams","type":"event"},{"inputs":[],"name":"DEFAULT_PAYLOAD_SIZE_LIMIT","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"NO_EXTRA_GAS","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"PT_SEND","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"PT_SEND_AND_CALL","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"circulatingSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint16","name":"_dstChainId","type":"uint16"},{"internalType":"bytes32","name":"_toAddress","type":"bytes32"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"bytes","name":"_payload","type":"bytes"},{"internalType":"uint64","name":"_dstGasForCall","type":"uint64"},{"internalType":"bool","name":"_useZro","type":"bool"},{"internalType":"bytes","name":"_adapterParams","type":"bytes"}],"name":"estimateSendAndCallFee","outputs":[{"internalType":"uint256","name":"nativeFee","type":"uint256"},{"internalType":"uint256","name":"zroFee","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint16","name":"_dstChainId","type":"uint16"},{"internalType":"bytes32","name":"_toAddress","type":"bytes32"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"bool","name":"_useZro","type":"bool"},{"internalType":"bytes","name":"_adapterParams","type":"bytes"}],"name":"estimateSendFee","outputs":[{"internalType":"uint256","name":"nativeFee","type":"uint256"},{"internalType":"uint256","name":"zroFee","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint16","name":"","type":"uint16"},{"internalType":"bytes","name":"","type":"bytes"},{"internalType":"uint64","name":"","type":"uint64"}],"name":"failedMessages","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint16","name":"_srcChainId","type":"uint16"},{"internalType":"bytes","name":"_srcAddress","type":"bytes"}],"name":"forceResumeReceive","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint16","name":"_version","type":"uint16"},{"internalType":"uint16","name":"_chainId","type":"uint16"},{"internalType":"address","name":"","type":"address"},{"internalType":"uint256","name":"_configType","type":"uint256"}],"name":"getConfig","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint16","name":"_remoteChainId","type":"uint16"}],"name":"getTrustedRemoteAddress","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"innerToken","outputs":[{"internalType":"contract IERC20","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint16","name":"_srcChainId","type":"uint16"},{"internalType":"bytes","name":"_srcAddress","type":"bytes"}],"name":"isTrustedRemote","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"ld2sdRate","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"lzEndpoint","outputs":[{"internalType":"contract ILzEndpoint","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint16","name":"_srcChainId","type":"uint16"},{"internalType":"bytes","name":"_srcAddress","type":"bytes"},{"internalType":"uint64","name":"_nonce","type":"uint64"},{"internalType":"bytes","name":"_payload","type":"bytes"}],"name":"lzReceive","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint16","name":"","type":"uint16"},{"internalType":"uint16","name":"","type":"uint16"}],"name":"minDstGasLookup","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"minterBurner","outputs":[{"internalType":"contract IMintableBurnable","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint16","name":"_srcChainId","type":"uint16"},{"internalType":"bytes","name":"_srcAddress","type":"bytes"},{"internalType":"uint64","name":"_nonce","type":"uint64"},{"internalType":"bytes","name":"_payload","type":"bytes"}],"name":"nonblockingLzReceive","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint16","name":"","type":"uint16"}],"name":"payloadSizeLimitLookup","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"precrime","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint16","name":"_srcChainId","type":"uint16"},{"internalType":"bytes","name":"_srcAddress","type":"bytes"},{"internalType":"uint64","name":"_nonce","type":"uint64"},{"internalType":"bytes","name":"_payload","type":"bytes"}],"name":"retryMessage","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"_from","type":"address"},{"internalType":"uint16","name":"_dstChainId","type":"uint16"},{"internalType":"bytes32","name":"_toAddress","type":"bytes32"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"bytes","name":"_payload","type":"bytes"},{"internalType":"uint64","name":"_dstGasForCall","type":"uint64"},{"components":[{"internalType":"address payable","name":"refundAddress","type":"address"},{"internalType":"address","name":"zroPaymentAddress","type":"address"},{"internalType":"bytes","name":"adapterParams","type":"bytes"}],"internalType":"struct ILzCommonOFT.LzCallParams","name":"_callParams","type":"tuple"}],"name":"sendAndCall","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"_from","type":"address"},{"internalType":"uint16","name":"_dstChainId","type":"uint16"},{"internalType":"bytes32","name":"_toAddress","type":"bytes32"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"components":[{"internalType":"address payable","name":"refundAddress","type":"address"},{"internalType":"address","name":"zroPaymentAddress","type":"address"},{"internalType":"bytes","name":"adapterParams","type":"bytes"}],"internalType":"struct ILzCommonOFT.LzCallParams","name":"_callParams","type":"tuple"}],"name":"sendFrom","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint16","name":"_version","type":"uint16"},{"internalType":"uint16","name":"_chainId","type":"uint16"},{"internalType":"uint256","name":"_configType","type":"uint256"},{"internalType":"bytes","name":"_config","type":"bytes"}],"name":"setConfig","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint16","name":"_dstChainId","type":"uint16"},{"internalType":"uint16","name":"_packetType","type":"uint16"},{"internalType":"uint256","name":"_minGas","type":"uint256"}],"name":"setMinDstGas","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint16","name":"_dstChainId","type":"uint16"},{"internalType":"uint256","name":"_size","type":"uint256"}],"name":"setPayloadSizeLimit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_precrime","type":"address"}],"name":"setPrecrime","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint16","name":"_version","type":"uint16"}],"name":"setReceiveVersion","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint16","name":"_version","type":"uint16"}],"name":"setSendVersion","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint16","name":"_remoteChainId","type":"uint16"},{"internalType":"bytes","name":"_path","type":"bytes"}],"name":"setTrustedRemote","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint16","name":"_remoteChainId","type":"uint16"},{"internalType":"bytes","name":"_remoteAddress","type":"bytes"}],"name":"setTrustedRemoteAddress","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bool","name":"_useCustomAdapterParams","type":"bool"}],"name":"setUseCustomAdapterParams","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"sharedDecimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes4","name":"interfaceId","type":"bytes4"}],"name":"supportsInterface","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"token","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint16","name":"","type":"uint16"}],"name":"trustedRemoteLookup","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"useCustomAdapterParams","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]'
ERC20_ABI = '[{"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"}]'

list_send = []
STR_DONE = '✅ '
STR_CANCEL = '❌ '

with open(f"private_keys.txt", "r") as f:
    WALLETS = [row.strip() for row in f]


DATA = {
    'ethereum' : {'chain': 'ETH', 'chain_id': 1, 'rpc': 'https://rpc.ankr.com/eth', 'scan': 'https://etherscan.io/tx', 'token': 'ETH', 'decimals': 6}, #

    'optimism' : {'chain': 'OPTIMISM', 'chain_id': 10, 'rpc': 'https://rpc.ankr.com/optimism', 'scan': 'https://optimistic.etherscan.io/tx', 'token': 'ETH', 'decimals': 6}, #

    'bsc' : {'chain': 'BNB', 'chain_id': 56, 'rpc': 'https://rpc.ankr.com/bsc', 'scan': 'https://bscscan.com/tx', 'token': 'BNB', 'decimals': 18}, #

    'polygon' : {'chain': 'MATIC', 'chain_id': 137, 'rpc': 'https://polygon-rpc.com', 'scan': 'https://polygonscan.com/tx', 'token': 'MATIC', 'decimals': 6}, #

    'arbitrum' : {'chain': 'ARBITRUM', 'chain_id': 42161, 'rpc': 'https://rpc.ankr.com/arbitrum', 'scan': 'https://arbiscan.io/tx', 'token': 'ETH', 'decimals': 6}, #

    'avalanche' : {'chain': 'AVAXC', 'chain_id': 43114, 'rpc': 'https://rpc.ankr.com/avalanche', 'scan': 'https://snowtrace.io/tx', 'token': 'AVAX', 'decimals': 6}, #

    'nova' : {'chain': 'NOVA', 'chain_id': 42170, 'rpc': 'https://nova.arbitrum.io/rpc', 'scan': 'https://nova.arbiscan.io/tx', 'token': 'ETH', 'decimals': 6},

    'fantom' : {'chain': 'FTM', 'chain_id': 250, 'rpc': 'https://rpc.ankr.com/fantom', 'scan': 'https://ftmscan.com/tx', 'token': 'FTM', 'decimals': 6}, #

    'core' : {'chain': 'CORE', 'chain_id': 1116, 'rpc': 'https://rpc.coredao.org', 'scan': 'https://scan.coredao.org/tx', 'token': 'CORE', 'decimals': 6},

    'celo' : {'chain': 'CELO', 'chain_id': 42220, 'rpc': 'https://forno.celo.org', 'scan': 'https://celoscan.io/tx', 'token': 'CELO', 'decimals': 18},

    'gnosis' : {'chain': 'Gnosis', 'chain_id': 100, 'rpc': 'https://rpc.gnosischain.com', 'scan': 'https://gnosisscan.io/tx', 'token': 'xDAI', 'decimals': 18},
}


def send_msg():
    try:
        str_send = '\n'.join(list_send)
        bot = telebot.TeleBot(TG_TOKEN)
        bot.send_message(TG_ID, str_send)
    except Exception as error:
        logger.error(error)


def evm_wallet(key):
    try:
        web3 = Web3(Web3.HTTPProvider(DATA['ethereum']['rpc']))
        wallet = web3.eth.account.from_key(key).address
        return wallet
    except:
        return key


def sleeping(*timing):
    if len(timing) == 2: x = random.randint(timing[0], timing[1])
    else: x = timing[0]
    for _ in tqdm(range(x), desc='sleep ', bar_format='{desc}: {n_fmt}/{total_fmt}'):
        time.sleep(1)

def shuffle_dct(dct):
    keys = list(dct.keys())
    random.shuffle(keys)
    new_dct = {key: dct[key] for key in keys}
    return new_dct


def sign_tx(web3, contract_txn, privatekey):
    signed_tx = web3.eth.account.sign_transaction(contract_txn, privatekey)
    raw_tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_hash = web3.to_hex(raw_tx_hash)

    return tx_hash

def check_data_token(web3, token_address):
    try:

        token_contract = web3.eth.contract(address=Web3.to_checksum_address(token_address), abi=ERC20_ABI)
        decimals = token_contract.functions.decimals().call()
        symbol = token_contract.functions.symbol().call()

        return token_contract, decimals, symbol

    except Exception as error:
        logger.error(error)


def get_0x_quote(chain, from_token, to_token, value, slippage):
    try:

        url_chains = {
            'ethereum': '',
            'bsc': 'bsc.',
            'arbitrum': 'arbitrum.',
            'optimism': 'optimism.',
            'polygon': 'polygon.',
            'fantom': 'fantom.',
            'avalanche': 'avalanche.',
            'celo': 'celo.',
        }

        url = f'https://{url_chains[chain]}api.0x.org/swap/v1/quote?buyToken={to_token}&sellToken={from_token}&sellAmount={value}&slippagePercentage={slippage / 100}'

        response = requests.get(url)

        if response.status_code == 200:
            result = [response.json()]
            return result

        else:
            logger.error(f'response.status_code : {response.status_code}')
            return False

    except Exception as error:
        logger.error(error)
        return False



def check_status_tx(chain, tx_hash, text='checking tx_status'):

    logger.info(f'{chain} : {text} - {tx_hash}')
    time_old = time.time()
    if chain == 'polygon':
        TO_WAIT = 30 # WAIT 30 MIN
    else:
        TO_WAIT = 5 # WAIT 5 MIN

    while True:
        if time.time() > time_old + TO_WAIT * 60:
            logger.warning(f'no tx found in {TO_WAIT} mins, trying again...')
            return False
        try:
            rpc_chain   = DATA[chain]['rpc']
            web3        = Web3(Web3.HTTPProvider(rpc_chain))
            status_     = web3.eth.get_transaction_receipt(tx_hash)
            status      = status_["status"]
            if status in [0, 1]:
                return status
            time.sleep(1)
        except Exception as error:
            # logger.info(f'error, try again : {error}')
            time.sleep(1)


def check_balance(privatekey, chain, address_contract=False):
    try:

        rpc_chain = DATA[chain]['rpc']
        web3 = Web3(Web3.HTTPProvider(rpc_chain))

        try:
            wallet = web3.eth.account.from_key(privatekey).address
        except:
            wallet = privatekey

        if address_contract == False:  # eth
            balance = web3.eth.get_balance(web3.to_checksum_address(wallet))
            token_decimal = 18
        else:
            token_contract, token_decimal, symbol = check_data_token(web3, address_contract)
            balance = token_contract.functions.balanceOf(web3.to_checksum_address(wallet)).call()

        human_readable = balance / 10 ** token_decimal

        return human_readable

    except Exception as error:
        logger.error(error)
        time.sleep(1)
        check_balance(privatekey, chain, address_contract)


def mim_tokens(chain):
    tokens = {
        'bsc'       : '0xfe19f0b51438fd612f6fd59c1dbb3ea319f433ba',
        'avalanche' : '0x130966628846BFd36ff31a822705796e8cb8C18D',
        'arbitrum'  : '0xfea7a6a0b346362bf88a9e4a88416b77a57d6c2a',
        'polygon'   : '0x49a0400587a7f65072c87c4910449fdcc5c47242',
    }

    return tokens[chain]

def abra_contracts(chain):
    contracts = {
        'bsc'       : '0x41d5a04b4e03dc27dc1f5c5a576ad2187bc601af',
        'avalanche' : '0xB3a66127cCB143bFB01D3AECd3cE9D17381B130d',
        'arbitrum'  : '0x957A8Af7894E76e16DB17c2A913496a4E60B7090',
        'polygon'   : '0xca0d86afc25c57a6d2aCdf331CaBd4C9CEE05533',
    }

    return contracts[chain]


# ==================================================================================================================



def zeroX_swap(privatekey, chain, retry=0):
    try:

        module_str = '0x_swap'

        amount_from, amount_to, min_gwei, max_gwei, slippage = value_0x_swap()

        from_token_address = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE'
        native = DATA[chain]['token']
        to_token_address = mim_tokens(chain)

        web3 = Web3(Web3.HTTPProvider(DATA[chain]['rpc']))


        to_token_contract, to_decimals, to_symbol = check_data_token(web3, to_token_address)

        account = web3.eth.account.from_key(privatekey)
        wallet = account.address

        amount = round(random.uniform(amount_from, amount_to) / PRICES_NATIVE[chain], 8)

        amount = amount * 0.999
        amount_to_swap = int(amount * 10 ** 18)

        json_data = get_0x_quote(chain, from_token_address, to_token_address, amount_to_swap, slippage)

        if json_data != False:
            contract_txn = {
                'from': wallet,
                'chainId': web3.eth.chain_id,
                'gasPrice': int(json_data[0]['gasPrice']),
                'nonce': web3.eth.get_transaction_count(wallet),
                'gas': int(json_data[0]['gas']),
                'to': Web3.to_checksum_address(json_data[0]['to']),
                'data': json_data[0]['data'],
                'value': int(json_data[0]['value']),
            }
            if chain == 'bsc':
                contract_txn['gasPrice'] = int(random.uniform(min_gwei, max_gwei) * 10 ** 9)

            contract_txn['gas'] = int(contract_txn['gas'] * 1.5)

            tx_hash = sign_tx(web3, contract_txn, privatekey)
            tx_link = f'{DATA[chain]["scan"]}/{tx_hash}'

            module_str = f'0x_swap : {round(amount, 5)} {native} => {to_symbol}'

            status = check_status_tx(chain, tx_hash, f'{round(amount, 5)} {native} => {to_symbol}')

            if status == 1:
                logger.success(f'{module_str} | {tx_link}')
                list_send.append(f'{STR_DONE}{module_str}')
            else:
                logger.error(f'{module_str} | tx is failed | {tx_link}')
                if retry < RETRY:
                    logger.info(f'try again in 10 sec.')
                    sleeping(10, 10)
                    zeroX_swap(privatekey, chain, retry + 1)

    except Exception as error:
        module_str = f'0x_swap'
        logger.error(f'{module_str} | error : {error}')
        if retry < RETRY:
            logger.info(f'try again in 10 sec.')
            sleeping(10, 10)
            zeroX_swap(privatekey, chain, retry + 1)
        else:
            list_send.append(f'{STR_CANCEL}{module_str}')


def mim_bridge(privatekey, from_chain, retry=0): # https://app.abracadabra.money/#/beam
    to_chain, min_gwei, max_gwei = value_mim()

    while True:
        try:
            module_str = f'mim_bridge : {from_chain} => {to_chain}'

            amount = check_balance(privatekey, from_chain, mim_tokens(from_chain)) / 10
            value       = int(amount * 10 ** 18)

            web3        = Web3(Web3.HTTPProvider(DATA[from_chain]['rpc']))
            account     = web3.eth.account.from_key(privatekey)
            wallet      = account.address


            abra_contract = web3.eth.contract(address=web3.to_checksum_address(abra_contracts(from_chain)), abi=ABRACADABRA_ABI)

            while True:
                fee = abra_contract.functions.estimateSendFee(
                    167, # moonriver chain id
                    '0x'+wallet[2:].rjust(64, '0'),
                    0,
                    True,
                    '0x'
                ).call()[0]


                tx = abra_contract.functions.sendFrom(
                    wallet,
                    167, # moonriver chain id
                    '0x' + wallet[2:].rjust(64, '0'),
                    value,
                    (wallet,
                    '0x0000000000000000000000000000000000000000',
                    f'0x000200000000000000000000000000000000000000000000000000000000000186a00000000000000000000000000000000000000000000000000000000000000000{wallet[2:]}')
                ).build_transaction({
                        "chainId": web3.eth.chain_id,
                        "from": wallet,
                        "nonce": web3.eth.get_transaction_count(wallet),
                        'gasPrice': web3.eth.gas_price,
                        "value": fee,
                })
                if from_chain == 'bsc':
                    tx['gasPrice'] = int(random.uniform(min_gwei, max_gwei) * 10 ** 9)

                tx['gas'] = web3.eth.estimate_gas(tx)

                tx_hash = sign_tx(web3, tx, privatekey)
                tx_link = f'{DATA[from_chain]["scan"]}/{tx_hash}'

                status = check_status_tx(from_chain, tx_hash, 'mim bridge')
                if status != False: break

            if status == 1:
                logger.success(f'{module_str} | {tx_link}')
                list_send.append(f'{STR_DONE}{module_str}')
                break

            else:
                if retry < RETRY:
                    logger.info(f'{module_str} | tx is failed, try again in 10 sec | {tx_link}')
                    sleeping(10, 10)
                    retry += 1
                else:
                    logger.error(f'{module_str} | tx is failed | {tx_link}')
                    list_send.append(f'{STR_CANCEL}{module_str} | tx is failed | {tx_link}')
                    return

        except Exception as error:
            if 'nonce too low' in str(error):
                logger.warning(f'{module_str} | {error}')
                sleeping(15)
            else:
                logger.error(f'{module_str} | {error}')
                if retry < RETRY:
                    logger.info(f'try again | {wallet}')
                    sleeping(10, 10)
                    retry += 1
                else:
                    list_send.append(f'{STR_CANCEL}{module_str}')
                    return


def get_native_prices():
    try:

        # logger.info('checking native prices')

        prices = {
            'ETH': 0, 'BNB': 0, 'AVAX': 0, 'MATIC': 0, 'FTM': 0,
        }

        for symbol in prices:

            url = f'https://api.binance.com/api/v3/ticker/price?symbol={symbol}USDT'

            response = requests.get(url)

            if response.status_code == 200:
                result = [response.json()]
                price = result[0]['price']
                prices[symbol] = float(price)
            else:
                logger.error(f'response.status_code : {response.status_code}. try again')
                time.sleep(5)
                return get_native_prices()

        data = {
            'avalanche': prices['AVAX'],
            'polygon': prices['MATIC'],  # MATIC
            'ethereum': prices['ETH'],  # ETH
            'bsc': prices['BNB'],  # BNB
            'arbitrum': prices['ETH'],  # ETH
            'optimism': prices['ETH'],  # ETH
            'fantom': prices['FTM'],  # FTM
            'zksync': prices['ETH'],  # ETH
        }

        return data

    except Exception as error:
        logger.error(f'error : {error}. try again')
        time.sleep(5)
        return get_native_prices()

PRICES_NATIVE = get_native_prices()
